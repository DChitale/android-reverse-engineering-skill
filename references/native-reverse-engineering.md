# Native Reverse Engineering with MT Manager MCP

Guide to analyzing and patching compiled native ELF shared libraries (`.so` files) embedded in Android APKs using the **MT Manager MCP** native engine.

---

## 1. Native Overview & Inspection

Android applications frequently store security verification, encryption keys, anti-tamper routines, and core logic in native `.so` files located under `lib/<abi>/`.

### Step 1: Inspect the ELF Binary
Start by calling `mt_apk_native_inspect`:

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so"
}
```

This returns:
- Target architecture (`ARM64`, `ARM32`, `X86_64`, `X86`) and endianness.
- Unfiltered item counts: symbols, dynamic symbols, relocations, init/fini array entries.
- Recommended `nextActions` for listing symbols and sections.

---

## 2. Locating JNI & Native Functions

Native methods declared in Java/Kotlin (e.g., `public native boolean verifyToken(...)`) are resolved either through standard JNI export naming or runtime dynamic registration via `RegisterNatives`.

### Enumerating JNI Exports

Call `mt_apk_native_list_items`:

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so",
  "itemKind": "dynamic_symbols",
  "namePrefix": "Java_",
  "limit": 100
}
```

Standard JNI exports follow the naming convention:
`Java_<package_with_underscores>_<Class>_<method>`
(e.g., `Java_com_example_app_SecurityManager_verifyToken`).

### Locating `JNI_OnLoad` & Dynamic Registrations

If JNI methods do not use the `Java_` prefix, the library registers them dynamically inside `JNI_OnLoad`:
1. Search for `JNI_OnLoad` using `mt_apk_native_list_items(itemKind="dynamic_symbols", namePrefix="JNI_OnLoad")`.
2. Inspect initialization arrays via `mt_apk_native_list_items(itemKind="init_array")` to find initializers executing before `JNI_OnLoad`.

---

## 3. Disassembly & Control-Flow Analysis

### Address Mapping

Before disassembling, check whether the target address is loaded and executable:

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so",
  "addressKind": "virtual",
  "address": "0x12340"
}
```
Ensure `data.mapping.isLoaded == true` and `data.mapping.isExecutable == true`.

### Disassembling Instructions

Call `mt_apk_native_disassemble`:

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so",
  "addressKind": "virtual",
  "address": "0x12340",
  "maxBytes": 64
}
```

Disassembly text is returned formatted as:
```text
0x12340: 08008052 mov w8, #1
0x12344: c0035fd6 ret
```
- Continuous windows follow `mt_apk_native_disassemble` using the returned `nextActions` directly.

### Control-Flow Graph (CFG)

To understand function complexity and branch topology without reading hundreds of raw assembly lines:

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so",
  "entryVirtualAddress": "0x12340",
  "outputMode": "summary",
  "maxAnalysisBytes": 16384,
  "maxBlocks": 256,
  "maxInstructions": 2000
}
```
- `outputMode="summary"`: gives basic block count, loop counts, and cyclomatic complexity.
- `outputMode="full"`: provides complete directed basic-block vertices and branching edges.

---

## 4. Native Cross-References (`mt_apk_native_xref`)

Find static callers, jump targets, or string references:

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so",
  "targetAddressKind": "virtual",
  "targetAddress": "0x12340",
  "scanKind": "both",
  "referenceKinds": ["call", "jump", "data"],
  "maxScanBytes": 1048576,
  "limit": 50
}
```
- For strings and data tables: use `scanKind="data"` and `referenceKinds=["data"]`.
- ARM32 binaries require specifying `sourceInstructionMode` (`"arm"` or `"thumb"`).

---

## 5. Patching Native Code

### Patching Instructions (Assembly Source)

Instead of manually calculating opcode hex values, use `mt_apk_native_patch_instructions`. `expectedHex` must be read **inside the same edit session** (base-workspace reads can mismatch):

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "<editSessionId>",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so",
  "addressKind": "virtual",
  "address": "0x12340",
  "instructionMode": "auto",
  "replacementAssembly": "mov w0, #1\nret",
  "expectedHex": "ff8300d1fd7b01a9",
  "paddingMode": "nop"
}
```
- `expectedHex` guards against stale reads **and** defines the equal-length patch window (max 256 bytes).
- The assembler encodes at the effective virtual address, so `b`/`bl`/`adrp` re-encode correctly.
- `paddingMode: "nop"` fills a replacement shorter than the window; `"none"` demands an exact length match.
- Address must be 4-byte aligned on AArch64/ARM. `addressKind: "file_offset"` (offset inside the SO entry) is the fallback when `mt_apk_native_map_address` reports a mapping miss.

### Patching Strings

To modify API endpoints, server hosts, or log tags embedded in `.so` files:

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "<editSessionId>",
  "locator": "zip_entry:lib/arm64-v8a/libsecurity.so",
  "addressKind": "file_offset",
  "address": "10452",
  "expectedText": "https://api.prod.example.com",
  "replacementText": "https://api.test.example.com",
  "paddingMode": "null_pad"
}
```

`paddingMode`: `"none"` (equal UTF-8 byte length), `"null_pad"` (NUL-terminated C string; growth consumes existing zero padding, window = max+1), `"space_pad"` (fixed-width visible string; growth consumes ASCII spaces). Patch window limit is 4096 UTF-8 bytes, and the tool never resizes the entry or relocates references.

> Dart/Flutter `libapp.so` follows the same tool path — see [flutter-reverse-engineering.md](flutter-reverse-engineering.md) for the blutter address plan and the Dart singleton patch recipes.
