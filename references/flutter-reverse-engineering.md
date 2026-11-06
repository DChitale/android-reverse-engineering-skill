# Flutter (Dart AOT) Reverse Engineering — blutter + MT Manager MCP

Analyzing and patching **Flutter** applications. A Flutter APK keeps almost no logic in Dex — the Dart code is compiled into `lib/<abi>/libapp.so` (a Dart AOT snapshot wrapped in an ELF container) and executed by `lib/<abi>/libflutter.so` (the Flutter engine). Dex/Smali analysis only exposes the thin `io.flutter` launcher; the real logic (API clients, license checks, feature gates, pinning) lives in `libapp.so`.

**Toolchain for this route:**

| Stage | Tool |
| :--- | :--- |
| Decompile Dart AOT → annotated assembly | [blutter](https://github.com/worawit/blutter) (external, arm64 only) |
| Read/index the blutter output, produce the address plan | [`scripts/flutter_apk_pipeline.py`](../scripts/flutter_apk_pipeline.py) |
| Map / disassemble / patch `libapp.so` inside the APK | **MT Manager MCP** — `mt_apk_native_*` |
| Repack + sign the patched APK | **MT Manager MCP** — `mt_apk_build(sign=true)` |

No radare2. No apktool. No uber-apk-signer. No manual APK extraction, no decoded folder, no local rebuild. `libapp.so` is patched **in place inside the APK zip entry** through the MCP native tools, and the APK is re-signed by MT.

**Sources for this guide:**

- Reverse engineering Flutter apps, Part 1 — Dart AOT snapshot internals: <https://blog.tst.sh/reverse-engineering-flutter-apps-part-1/>
- Reverse engineering Flutter apps, Part 2 — manual assembly analysis: <https://blog.tst.sh/reverse-engineering-flutter-apps-part-2/>
- blutter (worawit) — Dart AOT snapshot decompiler: <https://github.com/worawit/blutter>
- OWASP MASTG-TECH-0156 — Reverse Engineering Flutter Applications (Using Blutter): <https://mas.owasp.org/MASTG/techniques/android/MASTG-TECH-0156/#using-blutter>
- MT Manager MCP native ELF tools: [available-tools.md](available-tools.md#5-native-elf-reverse-engineering--lib-patching-so-binaries)

---

## 1. Required Input: the blutter `out` Folder (ask for this and nothing else)

> **Rule:** the only path to request from the user is the blutter **`out`** directory. Do not ask for a `libs` folder, a decoded APK folder, or an extracted `.so` — the APK inside MT Manager already contains `lib/arm64-v8a/libapp.so`, and MT patches it there.

```
<out>/
├── asm/             # annotated disassembly per Dart library -- the address source
├── pp.txt           # every Dart object in the object pool (URLs, keys, flags)
├── objs.txt         # nested pool dump
└── blutter_frida.js # optional Frida hook template
```

Validate before working:

```bash
python scripts/flutter_apk_pipeline.py check <out>
python scripts/flutter_apk_pipeline.py info  <out>   # libraries, function count, address range
```

`check` fails if `asm/` or `pp.txt` is missing — that folder is not a blutter output; ask again. If the user has not run blutter at all:

```bash
python scripts/flutter_apk_pipeline.py libs app.apk          # extracts lib/arm64-v8a/libapp.so + libflutter.so
python3 blutter.py app_libs blutter_out                      # user runs this externally
```

blutter builds the matching Dart VM from source (needs g++ ≥ 13 / Clang ≥ 16, Python 3 with `pyelftools` + `requests`) and is **Android arm64 only**. Obfuscated apps are only partially recovered (many functions stay unnamed).

The APK side is handled by MT Manager: if no APK is open, `mt_apk_list_available_apks` → `mt_apk_workspace_open(path=...)`; otherwise `mt_apk_workspace_open(path="mt://current-apk")`.

---

## 2. Dart AOT Snapshot Internals (orientation)

Foundational knowledge for reading `libapp.so` as an ELF. Useful when deciding where to patch; not needed to run the toolchain.

### 2.1 File layout

`objdump -T libapp.so` exposes exactly four symbols — the two Dart snapshots:

| Symbol | Content |
| :--- | :--- |
| `_kDartVmSnapshotInstructions` | Machine code for the VM isolate snapshot |
| `_kDartIsolateSnapshotInstructions` | Machine code for the main isolate snapshot (the app) |
| `_kDartVmSnapshotData` | Clustered data for the VM isolate snapshot |
| `_kDartIsolateSnapshotData` | Clustered data for the main isolate snapshot |

- `.text` holds the AOT machine code (loaded executable, base vaddr `0`); `.rodata` holds the clustered snapshot data.
- The snapshot is a **full serialized heap image of the VM right before `main()` runs** — not just code. It uses the undocumented *clustered snapshot* binary format: a `SerializationCluster` per class ID, written in three phases (**Trace** BFS from roots → **Alloc** class IDs/counts → **Fill** fields referencing other objects by ID).
- There is no index or size table — the snapshot must be fully deserialized to read anything. ROData (`RawOneByteString` clusters mapped directly from `.rodata`) is the only place where strings can be read without decoding.
- **Library, class, and function names survive release builds** (removing them would break stack traces). This is why blutter recovers usable names and why grepping its output works.

### 2.2 Base-0 addressing — why blutter addresses are MCP addresses

blutter disassembles the image **as if loaded at base 0**, so:

- the `// ** addr: 0x...` line on each function is the **ELF virtual address** of that function inside `libapp.so`;
- every printed instruction address is likewise a virtual address;
- for `libapp.so` the first `PT_LOAD` typically has `p_offset=0, p_vaddr=0`, so virtual address and file offset coincide — but never assume it, `mt_apk_native_map_address` reports the authoritative mapping.

Feed blutter addresses straight to the MCP native tools with `addressKind="virtual"`. Nothing to convert, nothing to extract.

---

## 3. Reading Dart AOT Assembly

### 3.1 Register conventions (ARM64)

| Register | Role |
| :--- | :--- |
| `x26` (THR) | Current thread — stack limit, heap bounds, VM state at version-specific offsets (e.g. stack limit `[x26, #0x48]`, heap top `#0x58`, heap limit `#0x60` in one Dart 3.x layout) |
| `x27` (PP) | Object pool — all constants (strings, ICs, call targets) load PP-relative (`ldr xN, [x27, #imm]`) |
| `x22` | VM singletons anchor in newer layouts — `null` itself, with `true` at `x22+0x20` / `false` at `x22+0x30` in the Dart 3.2.5 build used by r2flutter's AuthPass tutorial; older layouts load singletons THR-relative instead (verify per version) |
| `x28` | Write-barrier mask |
| `x15` | Dart's stack pointer — Dart AOT deviates from the ARM64 ABI and uses `x15` instead of `sp` |

(ARM32: `x5` = PP, `x10` = THR — moot here, blutter and this route are arm64 only.)

### 3.2 Typical function shape

```text
<prologue: enter frame, save PP/FP/LR>
<CheckStackOverflow: ldr x16, [THR, #stack_limit]; cmp sp, x16; b.cc stack_overflow>
ldr x0, [PP, #0x1234]      ; constant from the object pool (resolve in pp.txt)
bl 0x7abc000               ; call -- blutter prints the callee name in the comment
ldr x0, [THR, #0x60]       ; singleton (null/true/false) from thread
<epilogue: restore, ret>
```

Codegen patterns worth recognizing:

| Pattern | Meaning |
| :--- | :--- |
| `ldr xN, [PP, #off]` | Constant from object pool — resolve via `pp.txt` / `objs.txt` |
| `ldr xN, [THR, #off]` | Singleton or VM state (`null`, stack limit, heap top) |
| Smis (small ints) | Tagged pointers: value shifted left; heap objects have bit 0 set |
| Argument descriptor (`r4`) | Named/optional argument handling in callee prologues |
| Class-ID range compares | `is` type checks compile to class-ID comparisons |
| Allocation stubs + write barriers | Instance allocation and GC tri-color invariant upkeep |
| `unlinkedCall` stubs | Inline caches that patch their own pool entry after first execution |

Function prologues begin `stp x29, x30, [x15, #-0x10]!`; type checks load the object header with `ldur x16, [x0, #-0x1]`; static calls route through the pool as `ldr x16, [x27, #off]` + `blr`. All of this is visible in the `asm/` dump.

---

## 4. blutter Output → Target → Virtual Address

### 4.1 blutter `asm/` format

One file per Dart library, mirroring the class tree:

```text
// library: 'package:app/license.dart'
class LicenseGate {
  bool isPremium() {
    // ** addr: 0x1a2b3c, size: 0x2a8
    0x1a2b3c: stp x29, x30, [x15, #-0x10]!
    0x1a2b40: ldr x0, [x27, #0x1234]  ; true
    0x1a2b44: ret
  }
}
```

The signature line ends with `{`, the next line carries `// ** addr: 0x..., size: 0x...`. That address is the patch target.

### 4.2 Index the output

```bash
# keyword sweep over function + class names (gates, license, pinning, integrity, ...)
python scripts/flutter_apk_pipeline.py plan <out>

# explicit query
python scripts/flutter_apk_pipeline.py find <out> "isPremium|isActive|entitlement"

# whole app, plus URL/key harvest from pp.txt
python scripts/flutter_apk_pipeline.py plan <out> --any --strings

# machine-readable plan: addresses + ready-made mt_apk_native_disassemble args
python scripts/flutter_apk_pipeline.py plan <out> --grep "licen|premium" --json plan.json
```

Output columns: `VIRTUAL`, `SIZE`, `CLASS`, `FUNCTION`. `plan --json` emits every candidate with a pre-filled `disassembleArgs` block (`locator: zip_entry:lib/arm64-v8a/libapp.so`, `addressKind: "virtual"`) plus the MCP call order — copy the arguments straight into the tool calls.

Manual greps still work:

```bash
grep -rn "LicenseGate_isPremium" <out>/asm/
grep -rni "subscri\|pinning\|integrity\|trial" <out>/asm/
grep -rni "https://\|/v1/\|api_key" <out>/pp.txt
```

### 4.3 Confirm the target before patching

1. Read the function body in `asm/`; identify the branch/return that decides the gate.
2. Cross-check the address against a sibling function that returns a known boolean — copy the **same snapshot's** idiom instead of guessing (offset layouts change per Dart version).
3. Record `(virtual address, size, intended patch, reason)` — it becomes the changelog row and the patch call.

`blutter_frida.js` (when generated) gives a runtime hook to observe the same function without modifying anything first.

---

## 5. Patching `libapp.so` via MT Manager MCP (no radare2)

### 5.1 Equal-length rule (non-negotiable)

Dart AOT snapshots bake absolute offsets into the heap image. Only overwrite bytes **in place** — never insert, delete, or shift content. Renaming symbols or growing strings inside `.rodata` corrupts the snapshot. On the MCP side that means: `expectedHex` and the assembled replacement must cover the **same byte count** (use `paddingMode="nop"` to fill a shorter replacement).

### 5.2 The session-first order (this is the one people get wrong)

`expectedHex` is a stale-view guard that must come from **the same edit session and locator** you are about to patch. So:

| # | Call | Why |
| :--- | :--- | :--- |
| 1 | `mt_apk_workspace_open(path="mt://current-apk", temporary=false)` | get `workspaceId` |
| 2 | `mt_apk_native_inspect(locator="zip_entry:lib/arm64-v8a/libapp.so")` | confirm ELF is AArch64 and the entry exists |
| 3 | `mt_apk_session_create(workspaceId=...)` | get `editSessionId` — **before** disassembling |
| 4 | `mt_apk_native_map_address(... address="0x1a2b3c", addressKind="virtual")` | verify `isLoaded=true`, `isExecutable=true`, note `fileOffset` |
| 5 | `mt_apk_native_disassemble(workspaceId, editSessionId, ...)` | read the window **in the session** → this is your `expectedHex` |
| 6 | `mt_apk_native_patch_instructions(...)` | patch, guarded by that `expectedHex` |
| 7 | `mt_apk_session_check(workspaceId, editSessionId, runBuildChecks=true)` | validate staged changes |
| 8 | `mt_apk_build(workspaceId, editSessionId, sign=true, outputPath="flutter_patched.apk")` | repack + sign |

Worked example — force `LicenseGate.isPremium()` to return Dart `true`:

```jsonc
// 4. verify the address is file-backed executable code
{ "workspaceId": "ws_...", "editSessionId": "", "locator": "zip_entry:lib/arm64-v8a/libapp.so",
  "addressKind": "virtual", "address": "0x1a2b3c" }

// 5. disassemble inside the session (copy the byte column into expectedHex)
{ "workspaceId": "ws_...", "editSessionId": "es_...", "locator": "zip_entry:lib/arm64-v8a/libapp.so",
  "addressKind": "virtual", "address": "0x1a2b3c", "instructionMode": "auto",
  "maxBytes": 64, "maxInstructions": 16 }

// 6. patch: two instructions replace the whole prologue window; nop pads the rest
{ "workspaceId": "ws_...", "editSessionId": "es_...", "locator": "zip_entry:lib/arm64-v8a/libapp.so",
  "addressKind": "virtual", "address": "0x1a2b3c", "instructionMode": "auto",
  "expectedHex": "FD7BBFA9...",                    // bytes copied from step 5
  "replacementAssembly": "add x0, x22, #0x20\nret",
  "paddingMode": "nop" }
```

`replacementAssembly` is assembled at the **effective virtual address**, so PC-relative forms (`b`, `bl`, `adrp`) re-encode correctly — do not hand-hex those.

### 5.3 Patch recipes (AArch64)

| Goal | `replacementAssembly` | Bytes |
| :--- | :--- | :--- |
| Neutralize a call | `nop` | `1F2003D6` |
| Force an early return (void) | `ret` | `C0035FD6` |
| Return Dart `true` (x22 anchor) | `add x0, x22, #0x20` + `ret` | `C0820091 C0035FD6` |
| Return Dart `false` (x22 anchor) | `add x0, x22, #0x30` + `ret` | `C0C20091 C0035FD6` |
| Return int `0` / `1` | `mov w0, #0` / `mov w0, #1` | `00008052` / `20008052` |
| Return null pointer | `mov x0, #0` | `000080D2` |
| Skip a check + keep the body | `nop` over the conditional branch | `1F2003D6` |
| Change a compared constant | patch the `ldr`/`mov` immediate, body untouched | — |

The boolean singletons are **layout-dependent**. Before using the x22 recipe, confirm it on this snapshot: find a function known to return `true` and see whether it loads from `x22+0x20` or from a THR offset / PP slot — then mirror that exact sequence.

### 5.4 If `addressKind="virtual"` misses

```
mt_apk_native_map_address → isLoaded=false / isExecutable=false
```

Do not guess. Two causes: the blutter output is from a different build, or the address isn't file-backed code. Verify with the local lib when available:

```bash
python scripts/flutter_apk_pipeline.py map <out> --lib libapp.so --grep "isPremium"
# VIRTUAL      FILE_OFFSET   EXEC   FUNCTION
# 0x1a2b3c     0x1a2b3c      x      bool isPremium()
```

`MISS` means that address is not patchable code in this `libapp.so` — re-check the APK/build pairing. A hit gives you a `fileOffset` you can pass with `addressKind="file_offset"` (same call shape, no loaded-mapping requirement).

### 5.5 Strings and pool constants

- `mt_apk_native_patch_string` edits UTF-8 in `.rodata` in place (`paddingMode: "none" | "null_pad" | "space_pad"`; growth only into existing padding, 4096-byte window). Useful for base-URL swaps where the replacement is not longer than the slot.
- Never lengthen a Dart pool string that the snapshot references by offset — patch the consuming code path instead.
- `mt_apk_patch_bytes` is the raw fallback when an instruction window cannot be assembled (equal-length, with `expectedHex` guard).

---

## 6. Build, Install, Verify

1. `mt_apk_session_check(runBuildChecks=true)` — must be clean.
2. `mt_apk_build(sign=true, outputPath="flutter_patched.apk")` — MT repacks the zip and signs with its keystore profile; the output path is in the returned data.
3. Post-patch byte check: `mt_apk_read_bytes(locator, byteOffset=<patchedFileOffset>, maxBytes=16)` and compare against the `afterHex` the patch call returned.
4. Install: uninstall the original first — signature changed, so an in-place update fails, and **this wipes app data** (say so before doing it).
5. Runtime test against the actual goal: the gated screen opens, the paywall disappears, the pinned host is accepted, the app does not crash on launch.

**What breaks the build, and why:**

| Symptom | Cause | Response |
| :--- | :--- | :--- |
| Crash on launch, no Dart frames | Native integrity check over `libapp.so` (hash/CRC in a sibling `.so` or Java guard) | find the comparison (`native_strings` / smali search for the lib name, `crc`, `sha`), neutralize it too, rebuild |
| Patch rejected: `expectedHex` mismatch | disassembled outside the edit session, or the window spans two reads | re-disassemble inside the session, copy the exact byte column |
| Patch rejected: length | replacement longer than the window | shrink to the instruction count available, or patch a smaller branch instead |
| Works in debug, gate returns | gate also enforced server-side | this is not a client patch problem — see the WebView/API fallback in the Phase 10 report |
| App launches, feature still locked | a second gate (another screen/class) | widen the keyword sweep (`plan --any`) and patch every check that feeds the flag |

> **Patch hygiene:** keep the changelog row for every native patch — `zip_entry` locator, virtual address, `expectedHex` → `afterHex`, reason, and the verification call. Phase 10 requires it.
