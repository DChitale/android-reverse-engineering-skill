#!/usr/bin/env python3
"""Flutter (Dart AOT) pipeline: blutter output -> MT Manager MCP patch plan.

Route B of the apk-reverse-engineering-mt-manager skill.

The APK is never extracted, decompiled, rebuilt or re-signed locally. Patching
and repacking happen inside MT Manager over the MCP native ELF tools
(mt_apk_native_* + mt_apk_build) -- no apktool, no radare2, no signer jar.
This script only reads the blutter output folder and turns it into the exact
addresses/arguments those MCP calls need.

The only required input is the blutter `out` directory.

Subcommands:
  check [OUT]     Sanity-report the environment and, when given, a blutter
                  output folder (checks asm/ and pp.txt).
  plan OUT        Index every function in OUT/asm/ (name -> virtual address,
                  size, class, library) and print the patch candidates.
                  --grep/--any filter, --json writes a machine-readable plan,
                  --strings also scans pp.txt for URLs / keys / flags.
  find OUT QUERY  Shorthand for `plan OUT --grep QUERY`.
  libs APK        Extract libapp.so + libflutter.so from an APK so blutter can
                  be run. Only needed when the user has not run blutter yet.
  map OUT --lib   Translate the blutter virtual addresses into ELF file offsets
                  (fallback for mt_apk_native_* addressKind="file_offset").
  info OUT        Print the blutter snapshot summary: libraries, function
                  count, address range.

Address model (why this works without radare2):
  blutter disassembles with the image loaded at base 0, so the `// ** addr:`
  line and every instruction address it prints IS the ELF virtual address
  inside libapp.so. Feed it straight to mt_apk_native_map_address /
  mt_apk_native_disassemble / mt_apk_native_patch_instructions with
  addressKind="virtual". If a mapping ever misses, `map` gives the
  file_offset argument for the same bytes.
"""

import argparse
import json
import os
import re
import struct
import sys
import zipfile

LIB_LOCATOR = "zip_entry:lib/arm64-v8a/libapp.so"

# blutter writes: "    // ** addr: 0x1a2b3c, size: 0x2a8"
ADDR_RE = re.compile(r"//\s*\*\*\s*addr:\s*(0x[0-9a-fA-F]+)(?:\s*,\s*size:\s*(0x[0-9a-fA-F]+))?")
LIB_RE = re.compile(r"//\s*library:\s*'([^']+)'")
CLASS_RE = re.compile(r"^\s*class\s+(.+?)\s*(?:\{|$)")

# Default patch-candidate keywords: gates, checks, and trust decisions.
DEFAULT_GREP = (
    "licen|premium|subscri|purchase|paywall|entitle|trial|locked|unlock|"
    "pro$|vip|valid|verify|auth|pinning|certificate|integrity|"
    "root|emulator|debug|jailbreak|signature|isPurchased|isPro"
)

URL_RE = re.compile(r"https?://[^\s\"'<>]+")
FLAG_RE = re.compile(
    r"(api[_-]?key|secret|token|bearer|client[_-]?id|base[_-]?url|"
    r"endpoint|graphql|firebase|supabase|stripe|revenuecat)",
    re.IGNORECASE,
)


def info(msg):
    print("[flutter] " + msg)


def die(msg):
    print("[error] " + msg, file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# blutter output parsing
# --------------------------------------------------------------------------

def parse_asm(out_dir):
    """Return (functions, libraries) from OUT/asm/.

    functions: list of dicts {name, class, library, address, size, file}
    libraries: sorted list of library URIs (or folder names when blutter did
               not emit `// library:` headers).
    """
    asm_dir = os.path.join(out_dir, "asm")
    if not os.path.isdir(asm_dir):
        die("no asm/ folder in %s -- this is not a blutter output folder." % out_dir)

    functions = []
    libraries = set()

    for root, _dirs, files in os.walk(asm_dir):
        for fname in sorted(files):
            path = os.path.join(root, fname)
            rel = os.path.relpath(path, out_dir)
            library = None
            cls = ""
            pending = None
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    for raw in fh:
                        line = raw.rstrip("\r\n")

                        m = LIB_RE.search(line)
                        if m:
                            library = m.group(1)
                            libraries.add(library)
                            continue

                        stripped = line.strip()
                        if not stripped:
                            pending = None
                            continue

                        m = CLASS_RE.match(line)
                        if m:
                            cls = m.group(1).strip()
                            pending = None
                            continue

                        m = ADDR_RE.search(line)
                        if m:
                            name = pending or "<unknown>"
                            functions.append(
                                {
                                    "name": name,
                                    "class": cls,
                                    "library": library or os.path.basename(root),
                                    "address": int(m.group(1), 16),
                                    "size": int(m.group(2), 16) if m.group(2) else 0,
                                    "file": rel,
                                }
                            )
                            pending = None
                            continue

                        # blutter prints the signature line directly above the
                        # addr comment, terminated by "{".
                        if not stripped.startswith("//") and stripped.endswith("{"):
                            pending = stripped[:-1].strip()
                            continue

                        if not stripped.startswith("//"):
                            pending = None
            except OSError as exc:
                info("skip %s (%s)" % (rel, exc))

    if not functions:
        die("found no annotated functions under %s -- blutter built without "
            "code analysis, or the wrong folder was given." % asm_dir)

    for lib in {f["library"] for f in functions if f["library"]}:
        libraries.add(lib)

    return functions, sorted(libraries)


def scan_pp(out_dir, limit=40):
    """Pull URLs and credential-ish flags out of pp.txt."""
    pp = os.path.join(out_dir, "pp.txt")
    if not os.path.isfile(pp):
        return [], []
    urls, flags = [], []
    with open(pp, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for u in URL_RE.findall(line):
                if u not in urls:
                    urls.append(u)
            if FLAG_RE.search(line) and line.strip() not in flags:
                flags.append(line.strip())
    return urls[:limit], flags[:limit]


def filter_functions(functions, pattern, use_default):
    if not pattern and not use_default:
        return functions
    rx = re.compile(pattern or DEFAULT_GREP, re.IGNORECASE)
    return [f for f in functions if rx.search(f["name"]) or rx.search(f["class"])]


# --------------------------------------------------------------------------
# ELF helpers (only for the file_offset fallback)
# --------------------------------------------------------------------------

def elf_load_segments(path):
    with open(path, "rb") as fh:
        data = fh.read(64)
        if data[:4] != b"\x7fELF":
            die("not an ELF file: " + path)
        if data[4] != 2:
            die("not a 64-bit ELF (blutter only targets arm64): " + path)
        endian = "<" if data[5] == 1 else ">"
        e_phoff = struct.unpack_from(endian + "Q", data, 0x20)[0]
        e_phentsize = struct.unpack_from(endian + "H", data, 0x36)[0]
        e_phnum = struct.unpack_from(endian + "H", data, 0x38)[0]
        fh.seek(e_phoff)
        table = fh.read(e_phentsize * e_phnum)

    segs = []
    for i in range(e_phnum):
        off = i * e_phentsize
        p_type, p_flags = struct.unpack_from(endian + "II", table, off)
        if p_type != 1:  # PT_LOAD
            continue
        p_offset, p_vaddr = struct.unpack_from(endian + "QQ", table, off + 8)
        p_filesz = struct.unpack_from(endian + "Q", table, off + 32)[0]
        segs.append(
            {"offset": p_offset, "vaddr": p_vaddr, "filesz": p_filesz,
             "exec": bool(p_flags & 0x1)}
        )
    return segs


def va_to_offset(segs, va):
    for s in segs:
        if s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
            return s["offset"] + (va - s["vaddr"]), s["exec"]
    return None, False


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_check(args):
    print("python:   %s" % sys.version.split()[0])
    if not args.out:
        info("pass the blutter out directory to validate it: check <out>")
        return 0
    out = os.path.abspath(os.path.expanduser(args.out))
    ok = True
    for rel, label in (
        ("asm", "annotated disassembly (required)"),
        ("pp.txt", "object pool strings (required)"),
        ("objs.txt", "nested pool dump (optional)"),
        ("blutter_frida.js", "frida hook template (optional)"),
    ):
        p = os.path.join(out, rel)
        exists = os.path.exists(p)
        print("%-16s %-4s %s" % (rel, "ok" if exists else "--", label))
        if rel in ("asm", "pp.txt") and not exists:
            ok = False
    if not ok:
        die("incomplete blutter output. Run: python3 blutter.py "
            "<app>/lib/arm64-v8a <out>")
    fns, libs = parse_asm(out)
    info("%d functions across %d libraries" % (len(fns), len(libs)))
    return 0


def cmd_plan(args):
    out = os.path.abspath(os.path.expanduser(args.out))
    functions, libraries = parse_asm(out)
    if args.library:
        rx = re.compile(args.library, re.IGNORECASE)
        functions = [f for f in functions if f["library"] and rx.search(f["library"])]
    picked = filter_functions(functions, args.grep, args.any)
    picked.sort(key=lambda f: f["address"])
    if args.limit:
        picked = picked[: args.limit]

    print("blutter out: %s" % out)
    print("libraries:   %d | functions indexed: %d | candidates: %d"
          % (len(libraries), len(functions), len(picked)))
    print()

    if picked:
        print("%-14s %-8s %-34s %s" % ("VIRTUAL", "SIZE", "CLASS", "FUNCTION"))
        print("-" * 104)
        for f in picked:
            print("%-14s %-8s %-34s %s"
                  % (hex(f["address"]), hex(f["size"]) if f["size"] else "-",
                     (f["class"] or "-")[:34], f["name"][:96]))
    else:
        info("no function matched -- retry with --any to list everything, or "
             "broaden --grep")

    urls, flags = ([], [])
    if args.strings:
        urls, flags = scan_pp(out)
        if urls:
            print("\nURLs / endpoints in pp.txt:")
            for u in urls:
                print("  " + u)
        if flags:
            print("\nKey-ish pool strings in pp.txt:")
            for f in flags:
                print("  " + f[:160])

    if args.json:
        plan = {
            "blutterOut": out,
            "apkLocatorDefault": LIB_LOCATOR,
            "mcpFlow": [
                "mt_apk_workspace_open",
                "mt_apk_session_create",
                "mt_apk_native_map_address (verify isLoaded/isExecutable)",
                "mt_apk_native_disassemble (inside the edit session -> expectedHex)",
                "mt_apk_native_patch_instructions",
                "mt_apk_session_check (runBuildChecks=true)",
                "mt_apk_build (sign=true)",
            ],
            "candidates": [
                {
                    "name": f["name"],
                    "class": f["class"],
                    "library": f["library"],
                    "virtualAddress": hex(f["address"]),
                    "size": f["size"],
                    "asmFile": f["file"],
                    "disassembleArgs": {
                        "locator": LIB_LOCATOR,
                        "addressKind": "virtual",
                        "address": hex(f["address"]),
                        "instructionMode": "auto",
                        "maxBytes": 64,
                        "maxInstructions": 16,
                    },
                }
                for f in picked
            ],
            "urls": urls,
            "poolFlags": flags,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, indent=2)
        info("plan written -> %s" % os.path.abspath(args.json))

    print("\nnext: mt_apk_session_create, then disassemble the chosen virtual "
          "address INSIDE that session and patch with the returned bytes as "
          "expectedHex.")
    return 0


def cmd_find(args):
    args.grep = args.grep or args.query
    return cmd_plan(args)


def cmd_libs(args):
    apk = os.path.abspath(os.path.expanduser(args.apk))
    if not os.path.isfile(apk):
        die("APK not found: " + apk)
    out = os.path.abspath(os.path.expanduser(args.out or
                                             (os.path.splitext(apk)[0] + "_libs")))
    os.makedirs(out, exist_ok=True)
    wanted = ["lib/arm64-v8a/libapp.so", "lib/arm64-v8a/libflutter.so"]
    found = []
    with zipfile.ZipFile(apk) as zf:
        names = set(zf.namelist())
        for name in wanted:
            if name not in names:
                info("missing in APK: " + name)
                continue
            dest = os.path.join(out, os.path.basename(name))
            with zf.open(name) as src, open(dest, "wb") as dst:
                dst.write(src.read())
            found.append(dest)
            info("extracted -> %s (%d bytes)" % (dest, os.path.getsize(dest)))
    if not found:
        die("no arm64-v8a libapp.so/libflutter.so in this APK -- blutter cannot "
            "analyse it (arm64 only).")
    print("\nrun blutter:\n  python3 blutter.py \"%s\" \"%s\""
          % (out, os.path.splitext(os.path.basename(apk))[0] + "_blutter"))
    return 0


def cmd_map(args):
    out = os.path.abspath(os.path.expanduser(args.out))
    lib = os.path.abspath(os.path.expanduser(args.lib))
    if not os.path.isfile(lib):
        die("libapp.so not found: " + lib)
    functions, _libs = parse_asm(out)
    picked = filter_functions(functions, args.grep, args.any)
    picked.sort(key=lambda f: f["address"])
    segs = elf_load_segments(lib)

    print("lib:  %s" % lib)
    print("PT_LOAD segments: %s"
          % ", ".join("vaddr=%s off=%s %s"
                      % (hex(s["vaddr"]), hex(s["offset"]),
                         "X" if s["exec"] else "r")
                      for s in segs))
    print()
    print("%-14s %-14s %-6s %s" % ("VIRTUAL", "FILE_OFFSET", "EXEC", "FUNCTION"))
    print("-" * 96)
    misses = 0
    for f in picked:
        off, is_exec = va_to_offset(segs, f["address"])
        if off is None:
            misses += 1
            print("%-14s %-14s %-6s %s" % (hex(f["address"]), "MISS", "?", f["name"][:64]))
            continue
        print("%-14s %-14s %-6s %s"
              % (hex(f["address"]), hex(off), "x" if is_exec else "r", f["name"][:64]))
    if misses:
        info("%d address(es) did not map -- those are not patchable code in "
             "this libapp.so (stale blutter output, or a different build)."
             % misses)
        return 1
    return 0


def cmd_info(args):
    out = os.path.abspath(os.path.expanduser(args.out))
    functions, libraries = parse_asm(out)
    addrs = [f["address"] for f in functions]
    print("out:        %s" % out)
    print("libraries:  %d" % len(libraries))
    print("functions:  %d" % len(functions))
    print("addresses:  %s .. %s" % (hex(min(addrs)), hex(max(addrs))))
    print()
    for lib in libraries:
        count = sum(1 for f in functions if f["library"] == lib)
        print("  %-60s %5d fns" % (lib[:60], count))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Flutter (Dart AOT) pipeline: turn a blutter out folder into "
                    "MT Manager MCP native patch calls (no radare2, no apktool).")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("check", help="validate the environment and a blutter out folder")
    p.add_argument("out", nargs="?", default=None, help="blutter out directory")
    p.set_defaults(func=cmd_check)

    def plan_args(p):
        p.add_argument("out", help="blutter out directory (contains asm/ and pp.txt)")
        p.add_argument("--grep", default=None,
                       help="regex over function/class names (default: gate + check keywords)")
        p.add_argument("--any", action="store_true",
                       help="ignore keywords and list every function")
        p.add_argument("--library", default=None, help="regex filter on the Dart library URI")
        p.add_argument("--limit", type=int, default=None, help="max rows to print")
        p.add_argument("--strings", action="store_true",
                       help="also scan pp.txt for URLs and key-ish flags")
        p.add_argument("--json", default=None, help="write the plan as JSON to this path")

    p = sub.add_parser("plan", help="index functions and print patch candidates")
    plan_args(p)
    p.set_defaults(func=cmd_plan)

    p = sub.add_parser("find", help="plan filtered by one query")
    plan_args(p)
    p.add_argument("query", help="regex over function/class names")
    p.set_defaults(func=cmd_find)

    p = sub.add_parser("libs", help="extract libapp.so + libflutter.so for blutter")
    p.add_argument("apk", help="path to the Flutter APK")
    p.add_argument("-o", "--out", default=None, help="destination folder")
    p.set_defaults(func=cmd_libs)

    p = sub.add_parser("map", help="translate blutter VAs to ELF file offsets")
    p.add_argument("out", help="blutter out directory")
    p.add_argument("--lib", required=True, help="the libapp.so those addresses came from")
    p.add_argument("--grep", default=None, help="regex over function/class names")
    p.add_argument("--any", action="store_true", help="map every function")
    p.set_defaults(func=cmd_map)

    p = sub.add_parser("info", help="summarise a blutter out folder")
    p.add_argument("out", help="blutter out directory")
    p.set_defaults(func=cmd_info)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
