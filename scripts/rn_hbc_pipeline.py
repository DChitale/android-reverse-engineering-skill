#!/usr/bin/env python3
"""React Native (Hermes) pipeline: bundle extract/disasm/asm, round-trip
verification, repack, zipalign + apksigner signing.

Route C of the apk-reverse-engineering-mt-manager skill. React Native targets
are processed entirely with local tools -- no MT Manager MCP involved.

Subcommands:
  pull PACKAGE        Resolve installed APK paths via `adb shell pm path` and
                      pull base.apk plus every split into a folder.
  extract APK         Extract assets/index.android.bundle, print size +
                      sha256, and check the Hermes magic/version.
  disasm BUNDLE DIR   hbctool disasm -> instruction.hasm, metadata.json,
                      string.json.
  asm HASM_DIR OUT    hbctool asm (hasm dir -> .hbc).
  roundtrip BUNDLE H  Verification ladder: assemble the unmodified hasm dir H
                      back to HBC, re-disassemble, diff against the original
                      hasm (line-identical modulo CRLF) and hash-compare
                      against the original bundle (byte-identical). With
                      --patched-hasm, also assemble the patched hasm and diff
                      it against the baseline round-trip (lines + bytes).
  repack APK BUNDLE   Rewrite the APK replacing the bundle entry, preserving
                      entry order and compression types; the bundle goes back
                      STORED/uncompressed (Hermes mmaps it).
  sign APK            zipalign -p -f 4 + apksigner with a debug keystore
                      (auto-generated on first use).
  verify-apk APK      sha256 of the bundle entry inside an APK vs a bundle
                      file on disk.
  check               Report tool availability without downloading anything.

hbctool: pip's hbctool 0.1.5 only supports HBC <= 76. Use the Kirlif fork
(https://github.com/Kirlif/HBC-Tool, supports up to v99): clone it and pass
its checkout directory via --hbctool or the HBCTOOL_DIR env var; the script
drives it through a PYTHONPATH shim, no install step needed.

zipalign / apksigner resolution: --build-tools <dir> -> PATH -> newest match
under ANDROID_HOME / ANDROID_SDK_ROOT / %LOCALAPPDATA%/Android/Sdk
build-tools/*. keytool comes from JAVA_HOME or PATH. Signatures use a debug
keystore (the Play signing key is unobtainable); reinstalling over a Play
build requires uninstalling first, which wipes app data.
"""

import argparse
import difflib
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile

HERMES_MAGIC = b"\xc6\x1f\xbc\x03\xc1\x03\x19\x1f"  # uint64 LE 0x1F1903C103BC1FC6
DEFAULT_BUNDLE_ENTRY = "assets/index.android.bundle"
HASM_FILES = ("instruction.hasm", "metadata.json", "string.json")
DIFF_HEAD_LINES = 60


def info(msg):
    print("[pipeline] " + msg)


def die(msg, code=1):
    print("[error] " + msg, file=sys.stderr)
    sys.exit(code)


def abspath_expand(p):
    return os.path.abspath(os.path.expanduser(p))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, env=None):
    printable = " ".join('"' + c + '"' if " " in c else c for c in cmd)
    info("run: " + printable)
    return subprocess.run(cmd, env=env).returncode


def tools_dir():
    d = os.path.abspath("tools")
    os.makedirs(d, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# hbctool (Kirlif fork) shim
# ---------------------------------------------------------------------------

def hbctool_dir(cli_dir):
    d = cli_dir or os.environ.get("HBCTOOL_DIR")
    if not d:
        die("hbctool fork directory not set. Clone https://github.com/Kirlif/HBC-Tool "
            "and pass its checkout via --hbctool <dir> or the HBCTOOL_DIR env var "
            "(pip's hbctool 0.1.5 only supports HBC <= 76).")
    d = abspath_expand(d)
    if not os.path.isfile(os.path.join(d, "hbctool", "__init__.py")):
        die("no hbctool package under %s (expected <dir>/hbctool/__init__.py) -- "
            "point --hbctool / HBCTOOL_DIR at the Kirlif/HBC-Tool checkout root." % d)
    return d


def run_hbctool(fork_dir, hbc_args):
    """Run the fork in-process via the PYTHONPATH shim: python -c <shim> <args>."""
    shim = ("import sys; sys.argv=['hbctool']+sys.argv[1:]; "
            "import hbctool; hbctool.main()")
    env = os.environ.copy()
    env["PYTHONPATH"] = fork_dir + os.pathsep + env.get("PYTHONPATH", "")
    code = run([sys.executable, "-c", shim] + list(hbc_args), env=env)
    if code != 0:
        die("hbctool %s failed (exit %d)" % (hbc_args[0], code))


# ---------------------------------------------------------------------------
# Android build-tools / JDK tool resolution
# ---------------------------------------------------------------------------

def _exe_candidates(name):
    if sys.platform == "win32":
        return [name + ".exe", name + ".bat", name]
    return [name]


def _find_in(path_dir, name):
    for cand in _exe_candidates(name):
        p = os.path.join(path_dir, cand)
        if os.path.isfile(p):
            return p
    return None


def _dir_version_key(name):
    parts = re.findall(r"\d+", name)
    return [int(p) for p in parts] or [0]


def sdk_search_dirs():
    dirs = []
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(env)
        if v:
            dirs.append(os.path.join(v, "build-tools"))
    if sys.platform == "win32":
        local = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk")
        if local.strip("\\/"):
            dirs.append(os.path.join(local, "build-tools"))
    dirs.append(os.path.expanduser("~/Android/Sdk/build-tools"))
    dirs.append(os.path.expanduser("~/Library/Android/sdk/build-tools"))
    return [d for d in dirs if os.path.isdir(d)]


def find_build_tools(cli_dir=None):
    """Return a build-tools version dir, or None if the tools must come from PATH."""
    if cli_dir:
        if _find_in(abspath_expand(cli_dir), "zipalign") and \
           _find_in(abspath_expand(cli_dir), "apksigner"):
            return abspath_expand(cli_dir)
        die("--build-tools dir lacks zipalign/apksigner: " + cli_dir)
    for base in sdk_search_dirs():
        versions = sorted(os.listdir(base), key=_dir_version_key, reverse=True)
        for v in versions:
            if _find_in(os.path.join(base, v), "zipalign") and \
               _find_in(os.path.join(base, v), "apksigner"):
                return os.path.join(base, v)
    return None


def find_tool(name, build_tools):
    if build_tools:
        p = _find_in(build_tools, name)
        if p:
            return p
    for cand in _exe_candidates(name):
        p = shutil.which(cand)
        if p:
            return p
    die("%s not found (PATH%s). Install Android build-tools or pass "
        "--build-tools <dir>." % (name, " or build-tools dirs under ANDROID_HOME"
                                  if not build_tools else ""))


def find_keytool(quiet=False):
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        p = _find_in(os.path.join(java_home, "bin"), "keytool")
        if p:
            return p
    for cand in _exe_candidates("keytool"):
        p = shutil.which(cand)
        if p:
            return p
    if not quiet:
        die("keytool not found (PATH/JAVA_HOME). Install a JDK 8+.")
    return None


def ensure_keystore(cli_ks):
    ks = abspath_expand(cli_ks) if cli_ks else os.path.join(tools_dir(), "debug.keystore")
    if os.path.isfile(ks):
        return ks
    keytool = find_keytool()
    info("generating debug keystore -> " + ks)
    if run([keytool, "-genkeypair", "-v",
            "-keystore", ks, "-storepass", "android", "-keypass", "android",
            "-alias", "androiddebugkey", "-keyalg", "RSA", "-keysize", "2048",
            "-validity", "10000",
            "-dname", "CN=Android Debug,O=Android,C=US"]) != 0:
        die("keytool failed to generate the debug keystore")
    return ks


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_pull(args):
    adb = args.adb or shutil.which("adb") or "adb"
    out = abspath_expand(args.out)
    os.makedirs(out, exist_ok=True)
    res = subprocess.run([adb, "shell", "pm", "path", args.package],
                         capture_output=True, text=True)
    if res.returncode != 0:
        die("adb shell pm path failed: " + (res.stderr or "").strip())
    paths = [ln[len("package:"):].strip()
             for ln in res.stdout.splitlines() if ln.startswith("package:")]
    if not paths:
        die("no package: paths returned -- is '%s' installed on the device?" % args.package)
    for apk in paths:
        dest = os.path.join(out, os.path.basename(apk))
        if run([adb, "pull", apk, dest]) != 0:
            die("adb pull failed for " + apk)
        info("pulled -> " + dest)
    info("next: 'adb shell dumpsys package %s' for versionName/dataDir; the Hermes "
         "bundle lives in base.apk" % args.package)
    return 0


def cmd_extract(args):
    apk = abspath_expand(args.apk)
    if not os.path.isfile(apk):
        die("APK not found: " + apk)
    entry = args.entry
    with zipfile.ZipFile(apk) as zf:
        names = zf.namelist()
        if entry not in names:
            bundle_hits = [n for n in names if "bundle" in n.lower()]
            die("entry not found in APK: %s (candidates: %s)"
                % (entry, ", ".join(bundle_hits) or "none -- not a React Native APK?"))
        data = zf.read(entry)
    out = abspath_expand(args.out) if args.out else \
        os.path.splitext(apk)[0] + "_bundle.hbc"
    with open(out, "wb") as fh:
        fh.write(data)
    info("extracted %s -> %s (%d bytes)" % (entry, out, len(data)))
    print("size:   %d" % len(data))
    print("sha256: %s" % hashlib.sha256(data).hexdigest())
    if data[:8] == HERMES_MAGIC:
        (version,) = struct.unpack("<I", data[8:12])
        info("Hermes bytecode v%d detected" % version)
    else:
        print("[warn] head bytes %s are not the Hermes magic -- plain JS bundle? "
              "Patch it directly as text; no disassembly needed."
              % data[:8].hex())
    return 0


def cmd_disasm(args):
    bundle = abspath_expand(args.bundle)
    if not os.path.isfile(bundle):
        die("bundle not found: " + bundle)
    with open(bundle, "rb") as fh:
        head = fh.read(12)
    if head[:8] != HERMES_MAGIC:
        die("not Hermes bytecode (head %s) -- plain JS? Patch as text." % head[:8].hex())
    outdir = abspath_expand(args.outdir)
    run_hbctool(hbctool_dir(args.hbctool), ["disasm", bundle, outdir])
    info("disassembled -> %s (edit instruction.hasm only; never metadata.json "
         "or string.json)" % outdir)
    return 0


def cmd_asm(args):
    hasm_dir = abspath_expand(args.hasm_dir)
    for fname in HASM_FILES:
        if not os.path.isfile(os.path.join(hasm_dir, fname)):
            die("not a hbctool output dir (missing %s): %s" % (fname, hasm_dir))
    out = abspath_expand(args.out)
    run_hbctool(hbctool_dir(args.hbctool), ["asm", hasm_dir, out])
    info("assembled -> %s (sha256: %s)" % (out, sha256_file(out)))
    return 0


def _read_lines(path):
    with open(path, "rb") as fh:
        return fh.read().replace(b"\r\n", b"\n").split(b"\n")


def _diff_report(label_a, lines_a, label_b, lines_b):
    """Print a unified diff for changed file pairs; True when identical."""
    if lines_a == lines_b:
        return True
    diff = list(difflib.unified_diff(lines_a, lines_b,
                                     fromfile=label_a, tofile=label_b, lineterm=b""))
    print("\n".join(d.decode("utf-8", "replace") for d in diff[:DIFF_HEAD_LINES]))
    if len(diff) > DIFF_HEAD_LINES:
        print("... (%d more diff lines)" % (len(diff) - DIFF_HEAD_LINES))
    return False


def _binary_diff(path_a, path_b):
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        a, b = fa.read(), fb.read()
    if a == b:
        print("binary diff: byte-identical")
        return 0
    if len(a) != len(b):
        print("[error] binary diff: size differs (%d vs %d bytes) -- instruction "
              "length changed somewhere; the patch is invalid" % (len(a), len(b)))
        return -1
    offsets = [i for i in range(len(a)) if a[i] != b[i]]
    print("binary diff: %d byte(s) differ" % len(offsets))
    for off in offsets[:10]:
        print("  @0x%x: %02x -> %02x" % (off, a[off], b[off]))
    if len(offsets) > 10:
        print("  ... (%d more)" % (len(offsets) - 10))
    return len(offsets)


def cmd_roundtrip(args):
    bundle = abspath_expand(args.bundle)
    hasm_dir = abspath_expand(args.hasm_dir)
    if not os.path.isfile(bundle):
        die("bundle not found: " + bundle)
    for fname in HASM_FILES:
        if not os.path.isfile(os.path.join(hasm_dir, fname)):
            die("not a hbctool output dir (missing %s): %s" % (fname, hasm_dir))
    hbc = hbctool_dir(args.hbctool)
    workdir = abspath_expand(args.workdir) if args.workdir else \
        os.path.splitext(bundle)[0] + "_roundtrip"
    os.makedirs(workdir, exist_ok=True)

    failures = []

    # -- baseline: assemble the unmodified hasm and prove it losslessly round-trips
    base_hbc = os.path.join(workdir, "baseline.hbc")
    base_redis = os.path.join(workdir, "baseline_redisasm")
    info("step 1: assemble unmodified hasm -> baseline.hbc")
    run_hbctool(hbc, ["asm", hasm_dir, base_hbc])
    info("step 2: re-disassemble baseline.hbc")
    run_hbctool(hbc, ["disasm", base_hbc, base_redis])
    for fname in HASM_FILES:
        ok = _diff_report("original/" + fname, _read_lines(os.path.join(hasm_dir, fname)),
                          "roundtrip/" + fname, _read_lines(os.path.join(base_redis, fname)))
        if ok:
            info("hasm diff %s: line-identical" % fname)
        else:
            failures.append("hasm %s does not round-trip -- fix the toolchain before "
                            "trusting any patch" % fname)
    h_orig, h_rt = sha256_file(bundle), sha256_file(base_hbc)
    info("baseline.hbc sha256: %s (original: %s)" % (h_rt, h_orig))
    if h_orig == h_rt:
        info("baseline hash: byte-identical to the original bundle")
    elif args.allow_hash_mismatch:
        print("[warn] baseline hash differs from the original bundle "
              "(--allow-hash-mismatch); the hasm diffs above are then the only "
              "proof of losslessness")
    else:
        failures.append("baseline round-trip HBC differs from the original bundle "
                        "hash -- fix the toolchain or pass --allow-hash-mismatch")

    # -- patched: assemble the edited hasm and diff against the baseline
    if args.patched_hasm:
        patched_dir = abspath_expand(args.patched_hasm)
        for fname in HASM_FILES:
            if not os.path.isfile(os.path.join(patched_dir, fname)):
                die("not a hbctool output dir (missing %s): %s" % (fname, patched_dir))
        patched_hbc = os.path.join(workdir, "patched.hbc")
        patched_redis = os.path.join(workdir, "patched_redisasm")
        info("step 3: assemble patched hasm -> patched.hbc")
        run_hbctool(hbc, ["asm", patched_dir, patched_hbc])
        info("step 4: re-disassemble patched.hbc and diff against the baseline")
        run_hbctool(hbc, ["disasm", patched_hbc, patched_redis])
        changed = _diff_report("baseline/instruction.hasm",
                               _read_lines(os.path.join(base_redis, "instruction.hasm")),
                               "patched/instruction.hasm",
                               _read_lines(os.path.join(patched_redis, "instruction.hasm")))
        if changed:
            failures.append("patched hasm re-disassembly is line-identical to the "
                            "baseline -- the edit did not survive assembly")
        else:
            info("patched hasm diff: shown above -- confirm it is exactly your edit")
        nbytes = _binary_diff(base_hbc, patched_hbc)
        if nbytes < 0:
            failures.append("patched HBC size differs from baseline -- invalid patch")
        elif nbytes == 0:
            failures.append("patched HBC is byte-identical to baseline -- the edit "
                            "did not survive assembly")
        else:
            info("patched HBC: %d changed byte(s) vs baseline" % nbytes)
        info("patched bundle ready for repack: " + patched_hbc)

    if failures:
        for f in failures:
            print("[fail] " + f, file=sys.stderr)
        sys.exit(2)
    info("round-trip verification PASSED")
    return 0


def cmd_repack(args):
    apk = abspath_expand(args.apk)
    bundle = abspath_expand(args.bundle)
    if not os.path.isfile(apk):
        die("APK not found: " + apk)
    if not os.path.isfile(bundle):
        die("bundle not found: " + bundle)
    with open(bundle, "rb") as fh:
        bundle_data = fh.read()
    entry = args.entry
    out = abspath_expand(args.out) if args.out else \
        os.path.splitext(apk)[0] + "_repacked.apk"
    with zipfile.ZipFile(apk) as src, \
         zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        names = src.namelist()
        if entry not in names:
            die("entry not found in APK: %s" % entry)
        replaced = False
        for zinfo in src.infolist():
            ni = zipfile.ZipInfo(zinfo.filename, date_time=zinfo.date_time)
            ni.compress_type = zinfo.compress_type
            ni.external_attr = zinfo.external_attr
            ni.internal_attr = zinfo.internal_attr
            ni.create_system = zinfo.create_system
            ni.extra = b""  # stale alignment padding; zipalign regenerates it
            data = src.read(zinfo.filename)
            if zinfo.filename == entry:
                data = bundle_data
                replaced = True
                if not args.keep_bundle_compression:
                    ni.compress_type = zipfile.ZIP_STORED  # Hermes mmaps the bundle
            dst.writestr(ni, data)
        if not replaced:
            die("entry %s was not rewritten (duplicate-name bookkeeping bug)" % entry)
    info("repacked -> %s (bundle %s, %d bytes, sha256: %s)"
         % (out, "STORED" if not args.keep_bundle_compression else "original compression",
            len(bundle_data), hashlib.sha256(bundle_data).hexdigest()))
    info("next: python scripts/rn_hbc_pipeline.py sign %s" % out)
    return 0


def cmd_sign(args):
    apk = abspath_expand(args.apk)
    if not os.path.isfile(apk):
        die("APK not found: " + apk)
    bt = find_build_tools(args.build_tools)
    zipalign = find_tool("zipalign", bt)
    apksigner = find_tool("apksigner", bt)
    ks = ensure_keystore(args.keystore)
    stem = os.path.splitext(apk)[0]
    aligned = stem + "_aligned.apk"
    signed = abspath_expand(args.out) if args.out else stem + "-aligned-signed.apk"
    if run(zipalign + ["-p", "-f", "4", apk, aligned]) != 0:
        die("zipalign failed")
    if run(apksigner + ["sign",
                        "--ks", ks, "--ks-pass", "pass:android",
                        "--key-pass", "pass:android",
                        "--out", signed, aligned]) != 0:
        die("apksigner sign failed")
    run(apksigner + ["verify", "--print-certs", signed])
    info("signed -> " + signed)
    info("install note: uninstall the Play build first (signature mismatch) -- "
         "this wipes app data; split installs need every split re-signed and "
         "'adb install-multiple'")
    return 0


def cmd_verify_apk(args):
    apk = abspath_expand(args.apk)
    bundle = abspath_expand(args.bundle)
    if not os.path.isfile(apk):
        die("APK not found: " + apk)
    if not os.path.isfile(bundle):
        die("bundle not found: " + bundle)
    with zipfile.ZipFile(apk) as zf:
        if args.entry not in zf.namelist():
            die("entry not found in APK: " + args.entry)
        data = zf.read(args.entry)
    h_apk, h_disk = hashlib.sha256(data).hexdigest(), sha256_file(bundle)
    print("inside APK: %s" % h_apk)
    print("on disk:    %s" % h_disk)
    if h_apk != h_disk:
        die("bundle inside the APK does NOT match %s" % bundle, code=3)
    info("bundle inside the signed APK matches the patched bundle")
    return 0


def cmd_check(args):
    print("python:           %s" % sys.version.split()[0])
    adb = shutil.which("adb")
    print("adb:              %s" % (adb or "NOT FOUND (platform-tools)"))
    fork = args.hbctool or os.environ.get("HBCTOOL_DIR")
    if fork and os.path.isfile(os.path.join(abspath_expand(fork), "hbctool", "__init__.py")):
        print("hbctool (Kirlif): ok -> " + abspath_expand(fork))
    elif fork:
        print("hbctool (Kirlif): HBCTOOL_DIR/--hbctool set but no hbctool package under it")
    else:
        print("hbctool (Kirlif): not configured -- set HBCTOOL_DIR or pass --hbctool "
              "(pip hbctool 0.1.5 is NOT supported, HBC <= 76 only)")
    bt = find_build_tools(args.build_tools)
    for name in ("zipalign", "apksigner"):
        if bt and _find_in(bt, name):
            print("%s:           ok -> %s" % (name, _find_in(bt, name)))
        else:
            p = shutil.which(name) or (shutil.which(name + ".bat") if sys.platform == "win32" else None)
            print("%s:           %s" % (name, p or "NOT FOUND (Android build-tools; "
                                       "set ANDROID_HOME or --build-tools)"))
    if find_keytool(quiet=True):
        print("keytool:          ok")
    else:
        print("keytool:          NOT FOUND (JDK)")
    ks = os.path.join(tools_dir(), "debug.keystore")
    print("debug keystore:   %s (%s)" % (ks, "exists" if os.path.isfile(ks)
                                         else "generated on first sign"))
    return 0


# ---------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="React Native (Hermes) pipeline: bundle extract/disasm/asm, "
                    "round-trip verification, repack, zipalign + apksigner signing "
                    "(no MT Manager).")
    parser.add_argument("--hbctool", default=None,
                        help="Kirlif/HBC-Tool checkout dir (or HBCTOOL_DIR env)")
    parser.add_argument("--build-tools", default=None,
                        help="Android build-tools dir containing zipalign/apksigner")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("pull", help="pull base.apk + splits via adb for a package")
    p.add_argument("package")
    p.add_argument("-o", "--out", default="apks", help="output folder (default apks/)")
    p.add_argument("--adb", default=None, help="adb binary (default: PATH)")
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("extract", help="extract the Hermes bundle from an APK")
    p.add_argument("apk")
    p.add_argument("-o", "--out", default=None, help="output .hbc path")
    p.add_argument("--entry", default=DEFAULT_BUNDLE_ENTRY)
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("disasm", help="hbctool disasm (bundle -> hasm dir)")
    p.add_argument("bundle")
    p.add_argument("outdir")
    p.set_defaults(func=cmd_disasm)

    p = sub.add_parser("asm", help="hbctool asm (hasm dir -> bundle)")
    p.add_argument("hasm_dir")
    p.add_argument("out")
    p.set_defaults(func=cmd_asm)

    p = sub.add_parser("roundtrip", help="assemble + re-disassemble + diff/verify")
    p.add_argument("bundle", help="original .hbc (hash baseline)")
    p.add_argument("hasm_dir", help="hbctool output dir of the ORIGINAL bundle")
    p.add_argument("--patched-hasm", default=None,
                   help="hasm dir with the patch applied (edited copy)")
    p.add_argument("--workdir", default=None,
                   help="scratch dir (default <bundle>_roundtrip/)")
    p.add_argument("--allow-hash-mismatch", action="store_true",
                   help="warn instead of failing when the baseline HBC hash differs")
    p.set_defaults(func=cmd_roundtrip)

    p = sub.add_parser("repack", help="replace the bundle entry inside an APK")
    p.add_argument("apk", help="original APK (base.apk from the device)")
    p.add_argument("bundle", help="patched .hbc")
    p.add_argument("-o", "--out", default=None, help="output APK path")
    p.add_argument("--entry", default=DEFAULT_BUNDLE_ENTRY)
    p.add_argument("--keep-bundle-compression", action="store_true",
                   help="do not force STORED for the bundle (Hermes mmaps it)")
    p.set_defaults(func=cmd_repack)

    p = sub.add_parser("sign", help="zipalign -p -f 4 + apksigner (debug key)")
    p.add_argument("apk")
    p.add_argument("-o", "--out", default=None, help="signed output path")
    p.add_argument("--keystore", default=None,
                   help="keystore to sign with (default tools/debug.keystore, "
                        "generated as needed)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify-apk", help="sha256 of the bundle inside an APK")
    p.add_argument("apk")
    p.add_argument("bundle", help="bundle file the APK entry must match")
    p.add_argument("--entry", default=DEFAULT_BUNDLE_ENTRY)
    p.set_defaults(func=cmd_verify_apk)

    p = sub.add_parser("check", help="report tool availability")
    p.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
