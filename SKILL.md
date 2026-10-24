---
name: apk-reverse-engineering-mt-manager
description: Reverse engineer Android APKs, inspect Dex/Smali bytecode, trace HTTP API endpoints (Retrofit, OkHttp, Ktor, Volley), follow UI-to-network call flows, inspect and disassemble native ELF (.so) binaries, reverse engineer Flutter apps (Dart AOT snapshot analysis with blutter, patching libapp.so with radare2), and patch/rebuild APKs using the MT Manager MCP server. Use when the user wants to decompile, inspect, reverse engineer, or patch Android packages, extract API endpoints, analyze native libraries, or analyze/patch Flutter apps and libapp.so. 中文触发词：反编译APK、安卓逆向、提取API、分析安卓应用、反编译安卓、逆向工程、追踪调用链、提取接口、修改APK、Flutter逆向、分析libapp.so、修改libapp.so、Dart快照分析
---

# Android Reverse Engineering with MT Manager MCP

Comprehensive workflow for reverse engineering Android applications, extracting HTTP APIs, tracing call flows through Dex bytecode, analyzing native `.so` ELF binaries, and performing verified modifications using the **MT Manager MCP Server**.

---

## Quick Navigation

- [Phase 0: Workspace Setup & Fast Fingerprinting](#phase-0-workspace-setup--fast-fingerprinting)
- [Phase 1: Manifest & Architecture Survey](#phase-1-manifest--architecture-survey)
- [Phase 2: API & Network Endpoint Extraction](#phase-2-api--network-endpoint-extraction)
- [Phase 3: Bytecode Call Flow & Cross-Reference Tracing](#phase-3-bytecode-call-flow--cross-reference-tracing)
- [Phase 4: Native ELF (.so) Analysis & Disassembly](#phase-4-native-elf-so-analysis--disassembly)
- [Phase 5: Flutter (Dart AOT) Analysis & libapp.so Patching](#phase-5-flutter-dart-aot-analysis--libappso-patching)
- [Phase 6: Modification, Patching & APK Rebuilding](#phase-6-modification-patching--apk-rebuilding-optional)
- [Phase 7: Structured Reporting](#phase-7-structured-reporting)
- [References & Guides](#references--guides)

---

## Workflow

### Phase 0: Workspace Setup & Fast Fingerprinting

Before deep-diving into code, open the APK into a read-only workspace, verify its signing profile, and determine the application framework.

#### 1. Open the Workspace
Always begin by opening the target APK using `mt_apk_workspace_open`:
- **Current target**: `path="mt://current-apk"`
- **Available targets**: Use `mt_apk_list_available_apks()` to find local APKs.
- **Session persistence**:
  - `temporary=false` (Recommended): Retains workspace for comprehensive analysis and re-use.
  - `temporary=true`: For quick one-shot verifications that will be deleted afterwards.

```json
// Example call: mt_apk_workspace_open
{
  "path": "mt://current-apk",
  "temporary": false
}
```
*Save the returned `workspaceId` for all subsequent operations.*

#### 2. Signature & Metadata Inspection
Call `mt_apk_read_signature(workspaceId=...)` to inspect certificate digests, validity range, issuer, and signature schemes (v1, v2, v3).

#### 3. Fast Framework Fingerprinting
Check entry paths to identify non-native frameworks (Flutter, React Native, Cordova, Xamarin):
- Call `mt_apk_list(workspaceId=..., view="zip_entries", prefix="lib/", limit=200)`
- Call `mt_apk_list(workspaceId=..., view="zip_entries", prefix="assets/", limit=200)`

| Marker Detected | Architecture | Implication |
| :--- | :--- | :--- |
| `lib/libflutter.so`, `assets/flutter_assets/` | **Flutter** | Core logic lives compiled in `libapp.so`, not Dex. Pivot to [Phase 5 (Flutter/Dart AOT)](#phase-5-flutter-dart-aot-analysis--libappso-patching); Phases 1–3 only expose the launcher wrapper. |
| `assets/index.android.bundle` | **React Native** | Logic is in Hermes/JavaScript bundle. Extract and inspect with file tools. |
| `assets/www/index.html` | **Cordova / Capacitor** | Hybrid web application. Inspect HTML/JS assets under `assets/www/`. |
| `assemblies/`, `libmonosgen*.so` | **Xamarin / .NET MAUI** | Logic compiled into .NET DLL assemblies. |
| No framework markers | **Native Java/Kotlin** | Full Dex/Smali reverse engineering applies directly. |

---

### Phase 1: Manifest & Architecture Survey

#### 1. Read Decoded `AndroidManifest.xml`
Read the binary manifest decoded automatically as clean XML via `mt_apk_read_text`:

```json
// Example call: mt_apk_read_text
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "axml:AndroidManifest.xml",
  "startLine": 0,
  "startColumn": 0,
  "limit": 500,
  "maxChars": 49152
}
```

Identify:
- **Application Class**: `android:name` on `<application>` (runs first on launch).
- **Launcher Activity**: Activity containing `<action android:name="android.intent.action.MAIN"/>`.
- **Exported Components**: Activities, Services, and Receivers with `android:exported="true"`.
- **Permissions**: `INTERNET`, `ACCESS_NETWORK_STATE`, storage, and custom permissions.

#### 2. Survey Package Structure
Page through declared classes using `mt_apk_list`:

```json
// Example call: mt_apk_list
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "view": "dex_classes",
  "prefix": "",
  "limit": 200
}
```
Distinguish first-party application packages from third-party libraries (e.g., `androidx.*`, `com.google.*`, `io.reactivex.*`). Note packages containing `api`, `network`, `repo`, or `data`.

---

### Phase 2: API & Network Endpoint Extraction

Locate HTTP clients, API endpoints, headers, and configuration constants.

#### 1. Discover Endpoints via `mt_apk_search`
Perform targeted searches across Dex and resources:

```json
// Example: Search Retrofit GET annotations
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "target": "smali",
  "query": "Lretrofit2/http/GET;",
  "queryType": "literal",
  "caseSensitive": false,
  "matchMode": "contains",
  "prefix": "",
  "limit": 50
}
```

High-signal queries:
- **Retrofit**: `Lretrofit2/http/POST;`, `Lretrofit2/http/PUT;`, `Lretrofit2/http/DELETE;`
- **URLs / Paths**: `"https://"`, `"/api/v"`, `"/v1/"`, `"baseUrl"`
- **OkHttp Builders**: `Lokhttp3/Request$Builder;`, `Lokhttp3/HttpUrl$Builder;`
- **Ktor (Kotlin)**: `Lio/ktor/client/HttpClient;`, `BuildersKt;->get`

#### 2. Read Class Outlines
When an API interface is located (e.g. `dex_class:Lcom/example/api/UserApi;`), read its outline without downloading massive files:
```json
// Example call: mt_apk_dex_read_class_outline
{
  "workspaceId": "<workspaceId>",
  "locator": "dex_class:Lcom/example/api/UserApi;"
}
```
Follow up with `mt_apk_read_text` on specific method locators to inspect path annotations and parameter types.

#### 3. Extract Build Configurations
Search for `BuildConfig` constants:
```json
{
  "workspaceId": "<workspaceId>",
  "target": "smali",
  "query": "BuildConfig",
  "limit": 50
}
```
Read the matching `BuildConfig` classes to extract `BASE_URL`, environment hosts, and API tokens.

*See detailed patterns in [references/api-extraction-patterns.md](references/api-extraction-patterns.md).*

---

### Phase 3: Bytecode Call Flow & Cross-Reference Tracing

Trace execution from UI entry points down to network requests using direct Dex bytecode cross-references.

#### 1. Find Inbound References with `mt_apk_dex_xref`
Query callers of any method, field, or class:

```json
// Example call: mt_apk_dex_xref
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "dex_method:Lcom/example/api/AuthApi;->login(Ljava/lang/String;Ljava/lang/String;)Lretrofit2/Call;",
  "methodResolution": "dispatch",
  "limit": 50
}
```
- Use `methodResolution="dispatch"` for virtual methods and interface implementations.
- Use `methodResolution="exact"` for direct opcode reference equality.

#### 2. Read Caller Bytecode
Inspect calling methods directly via `mt_apk_read_text(locator=refs[i].sourceLocator)` to see parameters, token additions, and encryption wrapping.

#### 3. Traverse Upward to UI
Repeat cross-referencing to trace:
$$\text{API Method} \longleftarrow \text{Repository} \longleftarrow \text{ViewModel / Presenter} \longleftarrow \text{Activity / Fragment}$$

*See complete call-chain tracing recipes in [references/call-flow-analysis.md](references/call-flow-analysis.md).*

---

### Phase 4: Native ELF (`.so`) Analysis & Disassembly

When sensitive algorithms, cryptography, or licensing checks reside in native libraries:

1. **Inspect ELF Header**:
   Call `mt_apk_native_inspect(locator="zip_entry:lib/arm64-v8a/libnative.so")` to determine architecture (ARM64, ARM32, x86_64) and section counts.
2. **Enumerate Exported JNI Functions**:
   Call `mt_apk_native_list_items(locator="zip_entry:...", itemKind="dynamic_symbols", namePrefix="Java_")` to find exported native methods.
3. **Map Addresses & Disassemble**:
   - Check executable memory mapping with `mt_apk_native_map_address`.
   - Disassemble instruction windows with `mt_apk_native_disassemble`.
4. **Control Flow & Xrefs**:
   - Build control-flow graphs with `mt_apk_native_analyze_control_flow`.
   - Find static callers and string references with `mt_apk_native_xref`.

*See native instructions and examples in [references/native-reverse-engineering.md](references/native-reverse-engineering.md).*

---

### Phase 5: Flutter (Dart AOT) Analysis & `libapp.so` Patching

When Phase 0 detects Flutter, Dex analysis only exposes the thin `io.flutter` launcher — the business logic (API clients, license checks, feature gates) is compiled into `lib/arm64-v8a/libapp.so`, a Dart AOT snapshot inside an ELF container, executed by `libflutter.so`.

#### 0. Required Inputs: `libs` and `out` Folder Paths
**When the user asks to reverse engineer a Flutter app, ask for both folder paths before starting any analysis — never guess or assume them:**
- **`out`** — the blutter-decompiled `libapp.so` output (must contain `asm/` + `pp.txt`); this is what the analysis reads to find relevant functions.
- **`libs`** — the folder with the original `libapp.so` + `libflutter.so` (extracted `lib/arm64-v8a`); this is the binary radare2/r2flutter will edit.
Both must come from the same APK/build. If either is missing, tell the user to run blutter externally:
`python3 blutter.py <libs> <out>` (Android arm64 only; auto-detects the Dart version from `libflutter.so`).

#### 1. Method 1 — Dart AOT Snapshot Internals
Understand the target before touching it: the four exported snapshot symbols, `.text` machine code vs `.rodata` clustered heap data, ARM64 register conventions (`r26` = THR, `r27` = object pool), and why library/class/function names survive release builds.

#### 2. Method 2 — Manual Assembly-Level Analysis
Fingerprint the exact Dart version from `libflutter.so` (`Dart VM version` string → commit hash), recover the package structure from library URIs, and recognize AOT codegen patterns (PP-relative constant loads, Smi tagging, class-ID type checks, inline caches).

#### 3. Find Relevant Functions in the `out` Folder
Analyze the blutter output against the user's goal (license checks, SSL pinning, API endpoints, feature gates): grep `asm/` for `Class_method` symbol names and `pp.txt` for URLs/tokens; function headers carry `addr: 0x...` virtual addresses inside `libapp.so`; resolve `[pp+0xNN]` annotations via `pp.txt`/`objs.txt`.

#### 4. Edit `<libs>/libapp.so` with radare2 / r2flutter
Take the original binary from the user-provided `libs` folder (keep a pristine copy), open with `r2 -A` — or run `r2flutter -AAA` after installing the [r2flutter](https://github.com/radareorg/r2flutter) plugin to recover Dart function/class names directly in the session — seek to the address found in `out/asm/`, and patch in write mode (`wa nop` over a `bl`, `wa ret` for early return, `wx <hex>` for raw bytes) — **equal-length in-place overwrites only**; never shift snapshot bytes. Verify with `radiff2 -C`.

#### 5. Re-inject & Rebuild
Replay the radare2 patch as `mt_apk_patch_bytes` ranges (or `mt_apk_native_patch_instructions` with `addressKind="virtual"`) on `zip_entry:lib/arm64-v8a/libapp.so` inside an edit session, then `mt_apk_build(sign=true)`.

*Full guide — snapshot format tables, codegen patterns, radare2 recipes, and re-injection options — in [references/flutter-reverse-engineering.md](references/flutter-reverse-engineering.md).*

---

### Phase 6: Modification, Patching & APK Rebuilding (Optional)

When the goal includes modifying or verifying behavior changes:

1. **Create an Isolated Edit Session**:
   Call `mt_apk_session_create(workspaceId=...)` $\rightarrow$ obtain `editSessionId`.
2. **Apply Semantic Edits**:
   - **Smali / Code edits**: `mt_apk_edit_text` using `targetVersion` from `mt_apk_read_text`.
   - **Native Instruction patching**: `mt_apk_native_patch_instructions` (assembles instructions with safety checks).
   - **Native String patching**: `mt_apk_native_patch_string`.
   - **Resource edits**: `mt_apk_resource_edit` or `mt_apk_resource_add`.
   - **Raw byte fallbacks**: `mt_apk_patch_bytes`.
3. **Verify Staged Edits**:
   Call `mt_apk_session_check(workspaceId=..., editSessionId=..., runBuildChecks=true)` to test Smali compilation and Dex merging.
4. **Compile & Sign**:
   Call `mt_apk_build(workspaceId=..., editSessionId=..., sign=true, outputName="output_patched.apk")`.

---

### Phase 7: Structured Reporting

Deliver reverse engineering findings in two tiers:

#### Tier 1: Flat Inventory Table (Always)
A consolidated table covering every discovered endpoint:

| Host | Method | Path | Auth Type | Source Locator |
| :--- | :--- | :--- | :--- | :--- |
| `https://api.example.com` | `GET` | `/v1/user/profile` | Bearer Token | `dex_method:Lcom/example/api/UserApi;->getProfile()Lretrofit2/Call;` |
| `https://api.example.com` | `POST` | `/v1/auth/login` | None | `dex_method:Lcom/example/api/AuthApi;->login(...)Lretrofit2/Call;` |

#### Tier 2: Deep Dive (High-Value Flows)
Provide detailed parameter schemas, headers, response types, and UI call chains for critical endpoints (e.g. Auth, Payments, or anti-tamper logic).

---

## References & Guides

- [API Extraction Patterns](references/api-extraction-patterns.md) — Exact search patterns for Retrofit, OkHttp, Ktor, Volley, headers, and tokens.
- [Call Flow Analysis](references/call-flow-analysis.md) — Tracing UI-to-network call graphs using `mt_apk_dex_xref`.
- [Native Reverse Engineering](references/native-reverse-engineering.md) — ELF inspection, JNI enumeration, disassembly, CFG, and binary patching.
- [Flutter Reverse Engineering](references/flutter-reverse-engineering.md) — Dart AOT snapshot internals, manual assembly analysis, blutter output navigation, and editing `libapp.so` with radare2.
- [MT Manager Available Tools](references/available-tools.md) — Comprehensive reference table of all 57 MT Manager MCP tools and parameters.
