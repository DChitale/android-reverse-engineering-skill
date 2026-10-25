# Flutter (Dart AOT) Reverse Engineering

Analyzing and patching **Flutter** applications. A Flutter APK keeps almost no logic in Dex — the Dart code is compiled into `lib/<abi>/libapp.so` (a Dart AOT snapshot wrapped in an ELF container) and executed by `lib/<abi>/libflutter.so` (the Flutter engine). Dex/Smali analysis only exposes the thin `io.flutter` launcher; the real logic (API clients, license checks, feature gates, pinning) lives in `libapp.so`.

**Sources for this guide:**

- Reverse engineering Flutter apps, Part 1 — Dart AOT snapshot internals: <https://blog.tst.sh/reverse-engineering-flutter-apps-part-1/>
- Reverse engineering Flutter apps, Part 2 — manual assembly analysis: <https://blog.tst.sh/reverse-engineering-flutter-apps-part-2/>
- blutter (worawit) — Dart AOT snapshot decompiler: <https://github.com/worawit/blutter>
- OWASP MASTG-TECH-0156 — Reverse Engineering Flutter Applications (Using Blutter): <https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0156/#using-blutter>
- radare2 cheatsheet: <https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/>
- r2flutter — Dart/Flutter support for radare2: <https://github.com/radareorg/r2flutter>
- r2flutter docs — support matrix, version detection, strings/xrefs reliability, Dart asm notes, TLS-bypass tutorial: <https://github.com/radareorg/r2flutter/tree/main/doc>

---

## 1. Required Inputs: `libs` and `out` Folder Paths (ask the user first)

> **Rule:** When the user asks to reverse engineer a Flutter app, ask for the **`out`** folder path before starting any work — do not guess, assume, or fabricate it:
> 1. **`out`** — the blutter decompilation of the app's `libapp.so`. This is what the analysis reads to find relevant functions.
> 2. **`libs`** — the folder containing the original `libapp.so` and `libflutter.so`. In the standard Route B pipeline this is simply `<name>_decoded/lib/arm64-v8a` from the apktool decompile step; otherwise it is a folder the user extracted from the APK.
>
> Both must come from the same APK/build.

blutter downloads and compiles the matching Dart VM runtime from source (needs g++ >= 13 or Clang >= 16, Python 3 with `pyelftools` and `requests`); it cannot be assumed to exist in this environment, so the user runs it externally.

What to tell the user if they have not run blutter yet:

```bash
# Target: Android arm64 only (blutter does not support arm32 or iOS)
python3 blutter.py <libs> <out>     # e.g. python3 blutter.py app_decoded/lib/arm64-v8a blutter_out
```

- blutter auto-detects the Dart version from `libflutter.so` and builds the matching engine — do not substitute a different Dart version.
- If the APK has not been decompiled yet, run the pipeline script first (`flutter_apk_pipeline.py decompile <app.apk>`); `libs` is then `<name>_decoded/lib/arm64-v8a`. A raw `unzip target.apk -d apk_out "lib/arm64-v8a/*"` also works.
- Obfuscated apps are only partially supported (many functions stay unnamed).

**Validation checklist once the user provides the paths:**

| Path | Expected item | Meaning |
| :--- | :--- | :--- |
| `out/` | `asm/<library>/...` | Annotated disassembly per Dart library (the decompiled `libapp.so`) |
| `out/` | `pp.txt` | Every Dart object in the object pool (strings, URLs, paths) |
| `out/` | `objs.txt` | Nested dump of object-pool objects |
| `out/` | `blutter_frida.js` | Optional Frida hooking template for the target app |
| `libs/` | `libapp.so` | The Dart AOT binary to analyze with r2flutter and patch with radare2 |
| `libs/` | `libflutter.so` | Flutter engine — needed for version fingerprinting (`Dart VM version` string) |

If `out` lacks `asm/` or `pp.txt`, it is not a blutter output — ask again. If `libs` lacks `libapp.so`, ask for the correct folder.

---

## 2. Method 1 — Dart AOT Snapshot Internals (blog.tst.sh Part 1)

Foundational knowledge for reading `libapp.so` as an ELF. Use it to orient yourself before touching the blutter output or radare2.

### 2.1 File layout

`objdump -T libapp.so` exposes exactly four symbols — the two Dart snapshots:

| Symbol | Content |
| :--- | :--- |
| `_kDartVmSnapshotInstructions` | Machine code for the VM isolate snapshot |
| `_kDartIsolateSnapshotInstructions` | Machine code for the main isolate snapshot (the app) |
| `_kDartVmSnapshotData` | Clustered data for the VM isolate snapshot |
| `_kDartIsolateSnapshotData` | Clustered data for the main isolate snapshot |

- `.text` holds the AOT machine code (loaded as executable memory); `.rodata` holds the clustered snapshot data.
- The snapshot is a **full serialized heap image of the VM right before `main()` runs** — not just code. It uses the undocumented *clustered snapshot* binary format: a `SerializationCluster` per class ID, written in three phases (**Trace** BFS from roots → **Alloc** class IDs/counts → **Fill** fields referencing other objects by ID).
- There is no index or size table — the snapshot must be fully deserialized to read anything. ROData (`RawOneByteString` clusters mapped directly from `.rodata`) is the only place where strings can be read without decoding.
- **Library, class, and function names survive release builds** (removing them would break stack traces). This is why blutter can recover symbol names and why grepping the blutter output works so well.

### 2.2 Register conventions (ARM64)

| Register | Role |
| :--- | :--- |
| `r26`/`x26` (THR) | Current thread — stack limit, heap bounds, VM state at version-specific offsets (e.g. stack limit `[x26, #0x48]`, heap top `#0x58`, heap limit `#0x60` in one Dart 3.x layout) |
| `r27`/`x27` (PP) | Object pool — all constants (strings, ICs, call targets) load PP-relative (`ldr xN, [x27, #imm]`) |
| `r22` | VM singletons anchor in newer layouts — `null` itself, with `true` at `x22+0x20` / `false` at `x22+0x30` in the Dart 3.2.5 build of r2flutter's AuthPass tutorial; older layouts load singletons THR-relative instead (verify per version) |
| `r28` | Write-barrier mask |
| `r15` | Dart's stack pointer — Dart AOT deviates from the ARM64 ABI and uses `x15` instead of `sp` |

(On ARM32: `r5` = PP, `r10` = THR.) Dart AOT code comes from the JIT compiler, not clang, so it is less micro-optimized and stays closer to the IR — convenient for hand-reading.

---

## 3. Method 2 — Manual Assembly-Level Analysis (blog.tst.sh Part 2)

The workflow for reading the code once you know the snapshot layout. This is also the mindset for planning patches in radare2.

### Step 1: Fingerprint the Dart/Flutter version from `libflutter.so`

```bash
strings libflutter.so | grep -o "Dart VM version:.*"
# e.g. "Dart VM version: 2.8.0-dev.20.0 (stable) ... (hash: c547f5d933...)"
```

The hash maps to a commit in the `dart-sdk` GitHub repo, which pins the exact Flutter release. **Version matters**: object layouts and thread offsets change between releases, so blutter builds against the detected version and any manual offsets must be re-derived per version.

Faster alternative: the AOT snapshot itself embeds a 32-byte ASCII version hash in its header (magic `0xf5f5dcdc`, hash at offset `0x04` of the snapshot data). `r2flutter -H libapp.so` (or `-jH` for JSON) resolves that hash against its in-tree table and reports the detected Dart version directly, with a structural-probe fallback for unknown/dev-build hashes.

### Step 2: Recover the package structure

Enumerate library URIs from the snapshot (blutter prints these as `asm/<library-path>/` directories and symbol names). This reconstructs the source tree: the app's own package, plus dependencies (`protobuf`, `firebase`, `rx`, `bloc`, `provider`, ...). Field *names* are stripped; reconstruct classes from their implicit getters/setters.

### Step 3: Read the annotated disassembly

Typical AOT function shape (ARM64):

```text
<prologue: enter frame, save PP/FP/LR>
<CheckStackOverflow: ldr x16, [THR, #stack_limit_offset]; cmp sp, x16; b.cc stack_overflow>
ldr x0, [PP, #0x1234]      ; load constant from object pool (resolve in pp.txt)
bl 0x7abc000               ; static/dynamic call (blutter names it; r2 will not)
ldr x0, [THR, #0x60]       ; load singleton (null/true/false) from thread
<epilogue: restore, ret>
```

Codegen patterns to recognize:

| Pattern | Meaning |
| :--- | :--- |
| `ldr xN, [PP, #off]` | Constant from object pool — resolve via `pp.txt` / `objs.txt` |
| `ldr xN, [THR, #off]` | Singleton or VM state (`null`, stack limit, heap top) |
| Smis (small ints) | Tagged pointers: value shifted left; heap objects have bit 0 set |
| Argument descriptor (array in `r4`) | Named/optional argument handling in callee prologues |
| Class-ID range compares | `is` type checks compile to class-ID comparisons |
| Allocation stubs + write barriers | Instance allocation and GC tri-color invariant upkeep |
| `unlinkedCall` stubs | Inline caches that patch their own object-pool entry after first execution |

Grep-able identification patterns (r2 `/a` or `pd` scan): Dart function prologues begin `stp x29, x30, [x15, #-0x10]!`; type checks load the object header with `ldur x16, [x0, #-0x1]`; static calls route through the pool as `ldr x16, [x27, #off]` + `blr`.

---

## 4. Practical Workflow: blutter Output → Target → Address

1. **Recover the package structure**: list `asm/` directories; the app's own package (not `dart:*` / `package:flutter/*`) contains the business logic.
2. **Find functions relevant to the user's goal** (license/subscription checks, SSL pinning, API base URLs, feature gates, paywalls — ask what they want if unclear):
   ```bash
   grep -rn "ClassName_methodName" <out>/asm/      # when the class/method is already known
   grep -rni "license\|subscri\|verify\|pinning\|certificate\|trial" <out>/asm/
   grep -rni "api\|login\|token\|https://\|/v1/\|/v2/" <out>/pp.txt
   ```
3. **Read the function** in `asm/<lib>/<file>_<Class>-<method>.dart` — each function header carries `addr: 0x...`, the **virtual address inside `libapp.so`**, ready to seek to in radare2. `[pp+0xNN]` annotations resolve to `pp.txt` entries (API URLs, asset paths, flags).
4. **Harvest reference idioms** before patching: find a known `return true` / `return false` function in the same snapshot and note how it loads the boolean singleton (`ldr x0, [THR, #off]` or a PP-relative load). Offsets vary per Dart version — copying a verified sibling pattern is safer than guessing.
5. **Record** `(virtual address, original bytes, intended patch)` — this becomes the radare2 session applied to the decoded `<libs>/libapp.so`.

`blutter_frida.js` (if generated) provides a runtime hooking template for dynamic cross-checking of the static findings.

---

## 5. Editing `libapp.so` with radare2

The user's designated tool for editing `libapp.so` is **radare2** (command reference: [r2 cheatsheet](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/)). r2 can be driven interactively by the user or in reproducible batch mode via `r2 -w -qc '<commands>'`.

> **Equal-length rule:** Dart AOT snapshots bake absolute offsets into the heap image. Only overwrite bytes **in place** — never insert, delete, or shift content. Renaming symbols or growing strings inside `.rodata` corrupts the snapshot.

### Step 0: Locate the target binary and keep a pristine copy

The edit target is **`<libs>/libapp.so`** from the user-provided `libs` folder (only extract from the APK yourself if the user supplied just the `out` folder and no `libs`):

```bash
cp <libs>/libapp.so libapp.so.orig   # pristine copy for diffing/rollback — never edit this one
```

### Dart-aware analysis with r2flutter (optional but recommended)

[r2flutter](https://github.com/radareorg/r2flutter) is radareorg's official Dart/Flutter plugin for radare2. It parses the AOT snapshot inside `libapp.so` and applies the recovered function/class names, strings, ObjectPool values, flags, comments, and code references **directly to the r2 session** — a metadata and analysis aid, not a decompiler. Use it alongside blutter: blutter gives the richest annotated output outside r2; r2flutter gives named navigation inside the session where you actually patch.

Installation (build from source; requires radare2 6.2.2+ with dev headers on `PATH`):

```bash
git clone https://github.com/radareorg/r2flutter.git && cd r2flutter
make
make user-install     # per-user plugin (or: make r2 && sudo make install)
```

Standalone CLI inspection without opening r2:

```bash
bin/r2flutter -H libapp.so          # snapshot header + detected Dart version
bin/r2flutter -jH libapp.so         # header as JSON
bin/r2flutter -f libapp.so          # recovered function entrypoints/names
bin/r2flutter -l 20 -i libapp.so    # first 20 instruction-table entries
```

Key dump actions (`bin/r2flutter -h` for the full list; add `-j` for JSON, `-q` for values-only):

| Flag | Output |
| :--- | :--- |
| `-H` | Snapshot header/layout: magic `0xf5f5dcdc`, 32-byte version hash, detected Dart version |
| `-f` / `-i` | Function entrypoints + names / raw instruction-table entries |
| `-c` | Class/type names and surviving metadata |
| `-z` / `-zz` | Strings: strict (pool-reached only) / carving triage across `.rodata`, `__const`, UTF-16 runs |
| `-x`, `-xz`, `-xzz` | Flattened xrefs; combined with `-z`/`-zz` adds reverse refs (which class/field/method uses a string) |
| `-R` | Function flags with PP-relative pool offsets |
| `-O <addr>` / `-O pp+<off>` | Inspect one tagged Dart value: header, CID, length Smi, payload preview |
| `-HHH` | Structural ObjectPool/cluster decode — `pp_off` values match `ldr xN, [x27, #imm]` sites |
| `-m map.json` | Restore original function/class/field/method names from a Flutter `--save-obfuscation-map` file (strings are unaffected) |

Inside radare2, run the Dart-aware analysis pass, then navigate by name:

```bash
r2 -q libapp.so
[0x00000000]> r2flutter -AAA        # Dart-aware analysis: names, flags, classes, xrefs
[0x00000000]> afl~method            # list recovered functions, grep by method name
```

Notes (from the upstream [doc/ directory](https://github.com/radareorg/r2flutter/tree/main/doc)):
- **Inputs**: extracted `libapp.so`, a directory containing one, an iOS `.app` bundle (uses `Frameworks/App.framework/App`), or a direct AOT binary. AArch64 is the real target; other architectures get header/string work only.
- **Version support**: in-tree layout profiles cover Dart 2.10.0–3.14.0 (≈ Flutter 1.22–3.41), verified against each release's `class_id.h`. Best name recovery is on Dart 3.4.3+ (ObjectHeader + compressed pointers); older snapshots fall back to string/data-image heuristics.
- **Xref reality check**: object-graph and naming xrefs (`-x`, reverse refs from `-z`) are dumpable, but a function→callee call graph is not implemented — apply flags with `r2flutter -AAA`, then use r2's own `aar` + `axt` on the disassembly.
- **vs blutter**: r2flutter partially re-implements the deserializer and never boots the VM (blutter version-locks to the exact VM build), so names can differ slightly (e.g. `dyn:` trampolines, stub coverage). Cross-check recovered names against blutter's `asm/` output before patching.
- **Strings**: `-zz` carving uses heuristic lengths — confirm candidates with `-O <addr>` before trusting them.
- **FFI pivot**: for apps calling native libraries, correlate constant `DynamicLibrary.open` path strings and `lookup`/`lookupFunction` symbol strings (`-zz`, `-x`) with PP-relative call sites (`-HHH`), then continue in [native-reverse-engineering.md](native-reverse-engineering.md) against the target `.so`.

### Step 1: Analyze

```bash
r2 -A libapp.so
[0x00010000]> afl~...        # list functions (note: Dart symbols are NOT in .dynsym — navigate by blutter addresses or the names applied by r2flutter -AAA)
[0x00010000]> s 0x7abc000    # seek to the address from the blutter asm annotation
[0x07abc000]> pd 32          # disassemble the window
[0x07abc000]> axt @ 0x7abc000  # xrefs to this address
[0x00000000]> /x 20008052    # search hex patterns (e.g. mov w0,#1)
[0x00000000]> / loginFailed  # search strings in .rodata
```

### Step 2: Patch (write mode)

```bash
r2 -w -qc 's 0x7abc000; pd 8; wa nop; pd 8; q' libapp.so   # batch example
```

| Goal | radare2 | Bytes (ARM64) |
| :--- | :--- | :--- |
| Neutralize a call | `wa nop` over the `bl` | `1f2003d6` |
| Force an early return | `wa ret` at function entry | `c0035fd6` |
| Force a bool return | `add x0, x22, 0x20` (Dart `true`) + `ret` — see below | `c0820091c0035fd6` |
| Raw bytes | `wx 1f2003d6 @ 0x7abc000` | — |

The bool-return recipe comes from r2flutter's AuthPass TLS-bypass tutorial: in that Dart 3.2.5 build, `x22` anchors the VM singletons with `true` at `x22+0x20` and `false` at `x22+0x30`, so overwriting the target's entry with `add x0, x22, 0x20; ret` makes it always return `true`. The exact 8-byte patch used there (turning `_onBadCertificateWrapper` into an unconditional `return true`, disabling certificate validation):

```bash
cp app.so app.so.bak
r2 -q -w -n -c "s 0x3199d4" -c 'wx c0820091c0035fd6' -c q app.so   # add x0,x22,0x20 ; ret
r2 -qc 'p8 8 @ 0x3199d4' app.so                                     # verify
```

Offsets vary by Dart version — first disassemble a known boolean-returning function in the same snapshot and replicate its idiom. Upstream also ships an automated variant (`scripts/dart_cert_bypass.qjs`) that resolves the wrapper via flags and handles offset translation. Check `iS` (or `rabin2 -S`) beforehand to confirm how vaddr maps to file offset for the section being patched.

Useful write-mode commands: `wa` (write assembly), `wx` (write hex), `wt file [sz]` (dump bytes), `y n`/`yy` (yank/paste), `q!` (quit without saving), `wc` (commit write cache).

### Step 3: Verify

```bash
r2 -qc 'pd 8 @ 0x7abc000' libapp.so        # re-read the patched window
radiff2 -C libapp.so.orig libapp.so        # confirm ONLY intended bytes changed
```

Converting addresses for other tools: r2 seeks virtually. `iS` prints the section table (`vaddr` vs file `offset`) — for `libapp.so` they are typically identical, but verify before translating a virtual address into a file offset.

---

## 6. Rebuilding and Signing the Patched APK (No MT Manager)

Flutter targets never touch the MT Manager MCP server. After the radare2 patch on `<name>_decoded/lib/arm64-v8a/libapp.so` is verified with `radiff2 -C`, finish with the bundled pipeline script ([`scripts/flutter_apk_pipeline.py`](../scripts/flutter_apk_pipeline.py), stdlib-only Python 3):

1. **Rebuild** the decoded folder back into an APK (runs `apktool b`):
   ```bash
   python scripts/flutter_apk_pipeline.py rebuild <name>_decoded
   # -> <name>_rebuilt.apk next to the decoded folder
   ```
2. **Sign** with [uber-apk-signer](https://favr.dev/opensource/uber-apk-signer/) (zipalign + debug-sign in one pass):
   ```bash
   python scripts/flutter_apk_pipeline.py sign <name>_rebuilt.apk
   ```
   - The script **asks the user for the uber-apk-signer jar path first**; if it is not available, the latest release is auto-downloaded from <https://github.com/patrickfav/uber-apk-signer/releases> into `tools/`.
   - Result: `<name>_rebuilt-aligned-signed.apk` next to the input.

The script resolves apktool itself (`PATH` → `APKTOOL_JAR` env → `tools/apktool.jar`, auto-downloading from <https://github.com/iBotPeaches/Apktool/releases> when missing) and verifies Java 8+ is installed. Smali/resource tweaks to the launcher wrapper can be edited directly under `<name>_decoded/` before the rebuild.

> **Patch hygiene:** Dart AOT snapshots do not checksum themselves, but some apps add native integrity checks on `libapp.so` (hash comparison in `libflutter.so` sibling code or a Java-side guard). If the patched build crashes on launch, search for such verification (`strings`/`grep` for the `.so` name, CRC/hash references) and neutralize it too.
