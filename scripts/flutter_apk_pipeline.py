#!/usr/bin/env python3
"""Flutter APK pipeline: apktool decompile/rebuild + uber-apk-signer signing.

Route B of the apk-reverse-engineering-mt-manager skill. Flutter targets are
processed entirely with local tools -- no MT Manager MCP involved.

Subcommands:
  decompile [APK]     Decompile an APK with apktool (prompts for the path when
                      omitted). Produces <name>_decoded/ with smali, decoded
                      resources, and lib/arm64-v8a/libapp.so + libflutter.so.
  rebuild DIR         Rebuild a decoded folder into an APK with apktool.
                      Produces <name>_rebuilt.apk next to the folder.
  sign APK            Zipalign + sign with uber-apk-signer. Asks for the jar
                      path first; downloads the latest release if unavailable.
  check               Report java / apktool / uber-apk-signer availability
                      without downloading anything.

Tool resolution order:
  apktool         PATH -> APKTOOL_JAR env -> tools/apktool.jar (auto-downloaded)
  uber-apk-signer --signer-jar / UBER_APK_SIGNER_JAR env -> existing
                  tools/uber-apk-signer-*.jar -> ask the user -> auto-download

Download sources (Java 8+ required for both tools):
  apktool         https://github.com/iBotPeaches/Apktool/releases
  uber-apk-signer https://github.com/patrickfav/uber-apk-signer/releases
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

APKTOOL_REPO = "iBotPeaches/Apktool"
APKTOOL_URL = "https://github.com/iBotPeaches/Apktool/releases"
UBER_REPO = "patrickfav/uber-apk-signer"
UBER_URL = "https://github.com/patrickfav/uber-apk-signer/releases"


def tools_dir():
    d = os.path.abspath("tools")
    os.makedirs(d, exist_ok=True)
    return d


def info(msg):
    print("[pipeline] " + msg)


def die(msg):
    print("[error] " + msg, file=sys.stderr)
    sys.exit(1)


def ask(prompt):
    try:
        return input(prompt).strip().strip('"').strip("'")
    except EOFError:
        return ""


def find_java():
    java = shutil.which("java")
    if not java:
        die("Java not found on PATH. apktool and uber-apk-signer both require "
            "Java 8+ (e.g. https://adoptium.net). Install it and retry.")
    return java


def run(cmd):
    printable = " ".join('"' + c + '"' if " " in c else c for c in cmd)
    info("run: " + printable)
    return subprocess.run(cmd).returncode


def latest_jar_asset(repo, prefix):
    """Newest release asset named <prefix>*.jar -> (url, name, tag)."""
    url = "https://api.github.com/repos/%s/releases/latest" % repo
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "flutter-apk-pipeline",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        if name.startswith(prefix) and name.endswith(".jar"):
            return asset.get("browser_download_url"), name, data.get("tag_name", "?")
    return None, None, data.get("tag_name", "?")


def download(url, dest):
    info("downloading " + url)
    req = urllib.request.Request(url, headers={"User-Agent": "flutter-apk-pipeline"})
    with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)
    info("saved -> " + dest)


def resolve_apktool(download=True):
    """Return the apktool command prefix, downloading the jar when needed."""
    if shutil.which("apktool"):
        info("apktool found on PATH")
        return ["apktool"]
    env_jar = os.environ.get("APKTOOL_JAR")
    if env_jar and os.path.isfile(env_jar):
        info("apktool jar from APKTOOL_JAR: " + env_jar)
        return ["java", "-jar", env_jar]
    jar = os.path.join(tools_dir(), "apktool.jar")
    if os.path.isfile(jar):
        info("apktool jar: " + jar)
        return ["java", "-jar", jar]
    if not download:
        return None
    try:
        url, name, tag = latest_jar_asset(APKTOOL_REPO, "apktool_")
        if not url:
            die("no apktool .jar asset in the latest release (%s); download it "
                "manually from %s and pass --apktool-jar <path>" % (tag, APKTOOL_URL))
        info("installing apktool %s" % tag)
        download(url, jar)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        die("failed to download apktool (%s). Download the jar manually from %s "
            "and pass --apktool-jar <path>" % (exc, APKTOOL_URL))
    return ["java", "-jar", jar]


def resolve_signer(cli_jar, download=True):
    """Return the path to an uber-apk-signer jar.

    Order: --signer-jar / env -> existing tools/uber-apk-signer-*.jar ->
    ask the user -> download the latest release.
    """
    cand = cli_jar or os.environ.get("UBER_APK_SIGNER_JAR")
    if cand:
        if os.path.isfile(cand):
            return os.path.abspath(cand)
        die("uber-apk-signer jar not found: " + cand)
    for name in sorted(os.listdir(tools_dir())):
        if name.startswith("uber-apk-signer-") and name.endswith(".jar"):
            path = os.path.join(tools_dir(), name)
            info("uber-apk-signer jar: " + path)
            return path
    if not download:
        return None
    path = ask("Path to uber-apk-signer jar (press Enter to auto-download the "
               "latest release): ")
    if path:
        if os.path.isfile(path):
            return os.path.abspath(path)
        die("file not found: " + path)
    try:
        url, name, tag = latest_jar_asset(UBER_REPO, "uber-apk-signer-")
        if not url:
            die("no uber-apk-signer .jar asset in the latest release (%s); "
                "download it manually from %s" % (tag, UBER_URL))
        info("installing uber-apk-signer %s" % tag)
        dest = os.path.join(tools_dir(), name)
        download(url, dest)
        return dest
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        die("failed to download uber-apk-signer (%s). Download the jar manually "
            "from %s and place it in %s" % (exc, UBER_URL, tools_dir()))


def apktool_cmd(cli_jar):
    if cli_jar:
        if not os.path.isfile(cli_jar):
            die("apktool jar not found: " + cli_jar)
        return ["java", "-jar", os.path.abspath(cli_jar)]
    find_java()
    return resolve_apktool()


def cmd_decompile(args):
    apk = args.apk or ask("Path to the APK to decompile: ")
    if not apk:
        die("no APK path given")
    apk = os.path.abspath(os.path.expanduser(apk))
    if not os.path.isfile(apk):
        die("APK not found: " + apk)
    apktool = apktool_cmd(args.apktool_jar)
    outdir = os.path.join(
        os.path.dirname(apk), os.path.splitext(os.path.basename(apk))[0] + "_decoded"
    )
    if os.path.exists(outdir) and not args.force:
        die("output folder already exists: %s (remove it or pass --force)" % outdir)
    cmd = apktool + ["d", apk, "-o", outdir]
    if args.force:
        cmd.append("-f")
    if run(cmd) != 0:
        die("apktool decompile failed")
    info("decoded -> " + outdir)
    libdir = os.path.join(outdir, "lib", "arm64-v8a")
    if os.path.isdir(libdir):
        info("native libs -> " + libdir + " (libapp.so / libflutter.so)")
    else:
        info("note: no lib/arm64-v8a folder found in this APK")
    return 0


def cmd_rebuild(args):
    decoded = os.path.abspath(os.path.expanduser(args.dir))
    if not os.path.isdir(decoded):
        die("decoded folder not found: " + decoded)
    if not os.path.isfile(os.path.join(decoded, "apktool.yml")):
        die("not an apktool output folder (missing apktool.yml): " + decoded)
    apktool = apktool_cmd(args.apktool_jar)
    name = os.path.basename(os.path.normpath(decoded))
    if name.endswith("_decoded"):
        name = name[: -len("_decoded")]
    out = os.path.join(os.path.dirname(decoded), name + "_rebuilt.apk")
    if run(apktool + ["b", decoded, "-o", out]) != 0:
        die("apktool rebuild failed")
    info("rebuilt -> " + out)
    info("next: python flutter_apk_pipeline.py sign <apk>")
    return 0


def cmd_sign(args):
    apk = os.path.abspath(os.path.expanduser(args.apk))
    if not os.path.isfile(apk):
        die("APK not found: " + apk)
    java = find_java()
    jar = resolve_signer(args.signer_jar)
    info("signer jar: " + jar)
    if run([java, "-jar", jar, "--apks", apk]) != 0:
        die("uber-apk-signer failed")
    signed = os.path.splitext(apk)[0] + "-aligned-signed.apk"
    if os.path.isfile(signed):
        info("signed -> " + signed)
    else:
        info("done (check uber-apk-signer output above for the result path)")
    return 0


def cmd_check(args):
    java = shutil.which("java")
    print("java:             %s" % (java or "NOT FOUND (required for apktool + signer)"))
    apktool = resolve_apktool(download=False)
    if apktool:
        print("apktool:          ok -> " + " ".join(apktool))
    else:
        print("apktool:          not installed (auto-downloads on first use from %s)"
              % APKTOOL_URL)
    jar = resolve_signer(None, download=False)
    if jar:
        print("uber-apk-signer:  ok -> " + jar)
    else:
        print("uber-apk-signer:  not found (prompts for jar path, else downloads from %s)"
              % UBER_URL)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Flutter APK pipeline: apktool decompile/rebuild + "
                    "uber-apk-signer signing (no MT Manager).")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("decompile", help="decompile an APK with apktool")
    p.add_argument("apk", nargs="?", default=None, help="path to the APK (prompted if omitted)")
    p.add_argument("--force", action="store_true", help="overwrite an existing decoded folder")
    p.add_argument("--apktool-jar", default=None, help="path to apktool.jar (skips auto-detection)")
    p.set_defaults(func=cmd_decompile)

    p = sub.add_parser("rebuild", help="rebuild a decoded folder into an APK")
    p.add_argument("dir", help="apktool decoded folder (contains apktool.yml)")
    p.add_argument("--apktool-jar", default=None, help="path to apktool.jar (skips auto-detection)")
    p.set_defaults(func=cmd_rebuild)

    p = sub.add_parser("sign", help="zipalign + sign an APK with uber-apk-signer")
    p.add_argument("apk", help="path to the APK to sign")
    p.add_argument("--signer-jar", default=None, help="path to uber-apk-signer jar (prompted if omitted)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("check", help="report tool availability without downloading")
    p.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
