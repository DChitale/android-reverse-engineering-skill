---
name: apk-reverse-engineering-mt-manager
description: Reverse engineer and crack Android apps via three toolchains, selected by asking the user for the app type up front. Java/Kotlin apps use the MT Manager MCP server for Dex/Smali inspection, HTTP API endpoint extraction (Retrofit, OkHttp, Ktor, Volley), UI-to-network call-flow tracing, native ELF (.so) disassembly, in-place lib patching with a built-in assembler, verified patch/rebuild, and ad/tracker SDK detection & removal (stub AdMob, Unity, IronSource, Firebase Analytics, Adjust, AppsFlyer and 50+ more via the SDK registry). Flutter apps take only the blutter output directory as input — the MT Manager MCP native ELF assembler patches libapp.so in place inside the APK (mt_apk_native_patch_instructions, no radare2, no apktool) and mt_apk_build repacks and signs it. React Native apps use a local Hermes pipeline with NO MT Manager — the Kirlif HBC-Tool fork disassembles assets/index.android.bundle (HBC bytecode), gates are patched same-size in instruction.hasm behind a mandatory round-trip proof, and the APK is repacked with the bundle STORED + zipalign/apksigner signing. Use when the user wants to decompile, inspect, crack, reverse engineer, or patch Android packages, extract API endpoints, analyze native libraries, remove ads, remove trackers, strip telemetry, neutralize SDKs, analyze/patch Flutter apps and libapp.so, or analyze/patch React Native Hermes bundles. 中文触发词：反编译APK、安卓逆向、提取API、分析安卓应用、反编译安卓、逆向工程、追踪调用链、提取接口、修改APK、破解APP、去广告、移除广告、去除追踪器、移除SDK、隐私分析、Flutter逆向、分析libapp.so、修改libapp.so、Dart快照分析、React Native逆向、Hermes字节码、HBC补丁、修改index.android.bundle
---

# Android Reverse Engineering — Java & Flutter Routes (MT Manager MCP), React Native Route (Local Pipeline)

Three toolchains, selected up front by asking the user which kind of app it is:

- **Java/Kotlin app** → **Route A**: the **MT Manager MCP Server** handles workspace triage, Dex/Smali inspection, API extraction, call-flow tracing, native ELF analysis, and verified patch/rebuild. Native libs are patched **in place inside the APK** with `mt_apk_native_patch_instructions` (assembler built in — no extraction, no radare2). Ad/tracker SDK removal is built in (Phase 6).
- **Flutter app** → **Route B**: blutter output (`asm/` + `pp.txt`) is the only required input; the **MT Manager MCP native ELF assembler** maps blutter's base-0 virtual addresses onto `lib/arm64-v8a/libapp.so` inside the APK, patches them same-length, and `mt_apk_build(sign=true)` repacks and signs. **No radare2, no apktool, no uber-apk-signer.**
- **React Native app** → **Route C**: a local **Python pipeline** — the **Kirlif HBC-Tool fork** (hbctool) disassembles `assets/index.android.bundle` (Hermes bytecode) into hasm, gates are patched **same-size** in `instruction.hasm` behind a mandatory round-trip proof, and the APK is repacked (bundle STORED) + zipalign/apksigner-signed. **No MT Manager MCP for RN bundle work** (it still serves the Dex wrapper, e.g. Phase 6 ad-SDK sweeps).

---

## Quick Navigation

- [Phase 0: App Type Selection (Ask First)](#phase-0-app-type-selection-ask-first)
- **Route A — Java/Kotlin via MT Manager MCP**
  - [Phase 1: Workspace Setup and Signature Inspection](#phase-1-workspace-setup-and-signature-inspection)
  - [Phase 2: Manifest and Architecture Survey](#phase-2-manifest-and-architecture-survey)
  - [Phase 3: API and Network Endpoint Extraction](#phase-3-api-and-network-endpoint-extraction)
  - [Phase 4: Bytecode Call Flow and Cross-Reference Tracing](#phase-4-bytecode-call-flow-and-cross-reference-tracing)
  - [Phase 5: Native ELF (.so) Analysis and In-Place Lib Patching](#phase-5-native-elf-so-analysis-and-in-place-lib-patching)
  - [Phase 6: Ads and Tracker SDK Detection and Neutralization](#phase-6-ads-and-tracker-sdk-detection-and-neutralization)
  - [Phase 7: Modification, Patching and APK Rebuilding via Edit Sessions](#phase-7-modification-patching-and-apk-rebuilding-via-edit-sessions)
- **Route B — Flutter via blutter output + MT Manager MCP**
  - [Phase 8: Flutter — blutter Output to Patched APK](#phase-8-flutter--blutter-output-to-patched-apk)
- **Route C — React Native via local pipeline (no MT Manager)**
  - [Phase 9: React Native Decompile, Patch and Rebuild Pipeline (Hermes)](#phase-9-react-native-decompile-patch-and-rebuild-pipeline-hermes)
- [Phase 10: Structured Reporting](#phase-10-structured-reporting)
- [References & Guides](#references--guides)

---

## Workflow

### Phase 0: App Type Selection (Ask First)

**Before touching any tool, ask the user which type of app it is:**

> "Is the target app a **Java/Kotlin** (native Android) app, a **Flutter** app, or a **React Native** app?"

| Answer | Route |
| :--- | :--- |
| Java / Kotlin / "normal Android app" | **Route A** — Phases 1–7 (MT Manager MCP) |
| Flutter | **Route B** — Phase 8 (blutter `out` dir + MT Manager MCP native patch) |
| React Native / "it's built with JavaScript" | **Route C** — Phase 9 (local Hermes pipeline, no MT Manager) |

If the user is unsure, detect it locally (no MCP needed) by listing the APK's zip entries (`python -c "import zipfile; [print(n) for n in zipfile.ZipFile('target.apk').namelist()]"` or `unzip -l target.apk`):

| Marker Detected | Type | Route / Implication |
| :--- | :--- | :--- |
| `lib/*/libapp.so` + `libflutter.so`, or `assets/flutter_assets/` | **Flutter** | Route B — Dex only holds the thin `io.flutter` launcher; logic is in `libapp.so`, patched in place via the MCP native assembler. Only the blutter `out` folder is needed locally. |
| `assets/index.android.bundle` | **React Native** | Route C — Dex only wraps the RN runtime; all business logic is Hermes bytecode in the bundle. If the bundle does not start with the Hermes magic `C6 1F BC 03 C1 03 19 1F`, it is plain JS — patch it directly as text. |
| `assets/www/index.html` | **Cordova / Capacitor** | Route A for the wrapper; inspect HTML/JS under `assets/www/`. |
| `assemblies/`, `libmonosgen*.so` | **Xamarin / .NET MAUI** | Route A; logic compiled into .NET DLL assemblies. |
| None of the above | **Native Java/Kotlin** | Route A — full Dex/Smali reverse engineering applies. |

All routes finish at **Phase 10: Structured Reporting**.

---

### Route A: Java or Kotlin Apps via MT Manager MCP

#### Phase 1: Workspace Setup and Signature Inspection

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

---

#### Phase 2: Manifest and Architecture Survey

##### 1. Read Decoded `AndroidManifest.xml`
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

##### 2. Survey Package Structure
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

#### Phase 3: API and Network Endpoint Extraction

Locate HTTP clients, API endpoints, headers, and configuration constants.

##### 1. Discover Endpoints via `mt_apk_search`
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

##### 2. Read Class Outlines
When an API interface is located (e.g. `dex_class:Lcom/example/api/UserApi;`), read its outline without downloading massive files:
```json
// Example call: mt_apk_dex_read_class_outline
{
  "workspaceId": "<workspaceId>",
  "locator": "dex_class:Lcom/example/api/UserApi;"
}
```
Follow up with `mt_apk_read_text` on specific method locators to inspect path annotations and parameter types.

##### 3. Extract Build Configurations
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

#### Phase 4: Bytecode Call Flow and Cross-Reference Tracing

Trace execution from UI entry points down to network requests using direct Dex bytecode cross-references.

##### 1. Find Inbound References with `mt_apk_dex_xref`
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

##### 2. Read Caller Bytecode
Inspect calling methods directly via `mt_apk_read_text(locator=refs[i].sourceLocator)` to see parameters, token additions, and encryption wrapping.

##### 3. Traverse Upward to UI
Repeat cross-referencing to trace:
$$\text{API Method} \longleftarrow \text{Repository} \longleftarrow \text{ViewModel / Presenter} \longleftarrow \text{Activity / Fragment}$$

*See complete call-chain tracing recipes in [references/call-flow-analysis.md](references/call-flow-analysis.md).*

---

#### Phase 5: Native ELF (.so) Analysis and In-Place Lib Patching

Some Java/Kotlin apps move license checks, cryptography, or anti-tamper logic into native libraries.

**Analysis:**
1. **Inspect ELF Header**:
   Call `mt_apk_native_inspect(locator="zip_entry:lib/arm64-v8a/libnative.so")` to determine architecture (ARM64, ARM32, x86_64) and section counts.
2. **Enumerate Exported JNI Functions**:
   Call `mt_apk_native_list_items(locator="zip_entry:...", itemKind="dynamic_symbols", namePrefix="Java_")` to find exported native methods.
3. **Map Addresses & Disassemble**:
   - Check executable memory mapping with `mt_apk_native_map_address` (`isLoaded` + `isExecutable`).
   - Disassemble instruction windows with `mt_apk_native_disassemble`.
4. **Control Flow & Xrefs**:
   - Build control-flow graphs with `mt_apk_native_analyze_control_flow`.
   - Find static callers and string references with `mt_apk_native_xref`.

**When the lib actually needs patching (in place, no extraction):**
1. **Create the edit session first**: `mt_apk_session_create(workspaceId=...)` → `editSessionId`. `expectedHex` must be read from the same session, or the stale-view guard can mismatch.
2. **Read the window in the session**: `mt_apk_native_disassemble(workspaceId=..., editSessionId=..., locator="zip_entry:lib/arm64-v8a/libnative.so", addressKind="virtual", address="0x...", instructionMode="auto", maxBytes=32)` → copy the byte column.
3. **Patch with the assembler**: `mt_apk_native_patch_instructions(workspaceId=..., editSessionId=..., locator=..., addressKind="virtual", address="0x...", expectedHex=<step 2>, replacementAssembly="mov w0, #0\nret", paddingMode="nop")`. Equal-length only; PC-relative instructions re-encode at the effective VA. Instruction windows the assembler cannot express → `mt_apk_patch_bytes` (equal-length raw, same `expectedHex` discipline). UTF-8 strings in `.rodata` → `mt_apk_native_patch_string`.
4. **Check & build**: `mt_apk_session_check(workspaceId=..., editSessionId=..., runBuildChecks=true)` → `mt_apk_build(workspaceId=..., editSessionId=..., sign=true, outputPath="output_patched.apk")`.

*radare2/IDA remain optional external analysis aids — the patch itself is applied by MT. See [references/native-reverse-engineering.md](references/native-reverse-engineering.md).*

---

#### Phase 6: Ads and Tracker SDK Detection and Neutralization

When the goal is **removing ads, analytics, or trackers** from a Java/Kotlin app. Everything here is driven by the SDK registry and pattern guides in [references/ads-and-trackers/](references/ads-and-trackers/README.md) — 50+ ad / tracker / consent SDKs with exact package names, stub targets, and manifest components.

**Step 0 — Responsible-use gate (mandatory, before any patching):**
Warn the user and get explicit confirmation: stubbed `getInstance()`-style methods return `null` and can crash the app; features gated behind ads/analytics (rewarded content, A/B-tested UI) break; the rebuilt APK loses its original signature (Play Integrity fails, no Play-store updates over it); modifying an APK may violate its EULA and SDK provider terms — the user must have authorization. Always show the dry-run plan (Step 2) and get approval **before** applying edits.

**Step 1 — Detect (registry sweep):**
1. List registry entries via `mt_apk_list(view="dex_classes")` and match the app's packages against each entry's `packages` list (literal prefix match, e.g. `com.google.android.gms.ads`, `com.appsflyer`, `com.ironsource`).
2. Sweep smali per candidate package: `mt_apk_search(target="smali", query="Lcom/google/android/gms/ads/", queryType="literal")` — HIGH confidence needs SDK classes plus the entry's marker class; package-only or manifest-only is MEDIUM; app-code references, endpoint domains, or ID prefixes alone (`ca-app-pub-…`) are LOW.
3. Read `axml:AndroidManifest.xml` and match activities/services/receivers/providers/meta-data against each entry's `manifest_components` and `detection.manifest_names`.
4. Use `mt_apk_dex_xref` on each SDK's entry points to separate **active** SDKs (called from app packages) from **passive** ones (pulled in only as mediation adapters) — see `mediation-patterns.md`.
5. Report before touching anything:

| SDK | Category | Confidence | Active/Passive | Evidence | Neutralizable |
| :--- | :--- | :--- | :--- | :--- | :--- |
| Google AdMob | ads | HIGH | Active | classes + marker + manifest | yes (registry targets) |
| Unity Ads | ads | HIGH | Passive (AdMob adapter) | classes only | yes |
| Segment | analytics | HIGH | Active | classes only | **no** (detection-only entry) |

**Step 1b — Fast first pass (regex board):**
Unknown SDK mix, or a time-boxed sweep? Run the TDOhex three-rule board from `regex-batch-blocking.md` before the per-SDK stubs:
1. **Count before cutting** — `mt_apk_search(target="smali", queryType="regex", query=<rule>)`; read the class list for app-code false positives (any package segment named `ads` matches the path alternation).
2. **Void rule** (`invoke …()V` on an ad-SDK path) → `nop`; **boolean rule** (`()Z` + `move-result`) → `const/4 $9, 0x0`, which replaces both lines and keeps the register defined; **string rule** (ad/tracker hosts) → `"127.0.0.1"`, applied last.
3. `mt_apk_session_check(runBuildChecks=true)` is the referee — a single class the Dex verifier rejects fails the build; revert that method and move on.
- Blast radius is inline in that guide: the string alternation also covers `analytics`, `crashlytics`, `gstatic`, `cloudfront`, `mapbox`, `googleapis` — a privacy-max build accepts the collateral, a feature-preserving build prunes the list first.
- The board cannot see reflection/JNI paths (Unity, IronSource adapters, AppLovin `impl`) or in-house WebView creatives. Those still need the registry stubs below.


**Step 2 — Neutralize (dry-run plan → edit session):**
Present the plan first: for each confirmed SDK, which methods get stubbed at which depth, and which manifest components get disabled. Only after user approval, open an edit session (Phase 7) and:
1. **Stub method bodies** per the registry `targets` (skip what Step 1b already flattened) using `mt_apk_read_text` + `mt_apk_edit_text` on each `dex_method:` locator — replace the body with the stub recipe for its return type (`return-void`, `const/4 v0, 0x0` + `return-object v0` for null, etc.; full catalog in `smali-patterns.md`):
   - **Depth 1** (default, safest): `entry_points` only (initialize / start).
   - **Depth 2**: + `ad_operations` (load / show / cache) — safety net if init is bypassed.
   - **Depth 3**: + `deep_patterns` (bulk internal stubs) — aggressive, version-dependent.
2. **Disable — never remove — SDK manifest components**: add `android:enabled="false"` via `mt_apk_edit_text` on `axml:AndroidManifest.xml`. Disabling preserves the XML structure; removing risks resource-reference breakage.
3. **Consent apps** (Google UMP / IAB TCF): instead of plain stubs, use the reject-all `IABTCF_*` SharedPreferences injection described in `consent-neutralization.md` — it makes every TCF-honoring SDK self-limit.
4. Entries without `targets` are **detection-only** — report them, don't stub (`registry-backlog.md` lists gaps).

**Step 3 — Watch out for:**
- **In-house ad wrappers**: an app-owned package driving the network SDKs and serving WebView/MRAID "house" ads — neutralizing every registry SDK does not stop it. Registry entries flagged `in_house_wrapper: true` cover known ones (e.g. `com.rovio.beacon`, `guru.ads.fusion`); otherwise discover the wrapper's init/load entry points manually.
- **R8/ProGuard obfuscation** renames SDK classes so registry matching fails — fall back to endpoint domains, app-ID prefixes, and manifest `meta-data` names (they survive obfuscation) to locate the SDK, then identify its init methods by reading the smali.
- **ContentProvider auto-init** (Firebase, Facebook): disabling the provider in the manifest is often enough; the SDK code can stay.
- **Anti-tamper protection**: `com.pairip.*` classes (Play PairIP signature-VM) or manifest-declared components missing from `dex_classes` (packers) mean a rebuilt + re-signed APK **will not run** — warn the user before rebuilding. Never attempt to defeat the protection; report it.
- **Native `.so` integrity checks** in ad SDKs (AdMob, IronSource) may detect smali tampering.
- **Flutter apps**: ad/tracker SDKs are compiled into `libapp.so` — detect via `pp.txt`/`asm/` greps in the blutter output (domains, SDK keys, `GoogleMobileAds`, `FirebaseAnalytics` symbols) using `flutter_apk_pipeline.py plan <out> --strings`; there are no smali stubs to make. Neutralization is `mt_apk_native_patch_instructions` on the Dart init/load functions, or network-level domain blocking.

**Step 4 — Verify & report:** `mt_apk_session_check(runBuildChecks=true)` → `mt_apk_build(sign=true)` → every stubbed method and disabled component becomes a row in the Phase 10 Modification Changelog.

---

#### Phase 7: Modification, Patching and APK Rebuilding via Edit Sessions

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
5. **Record Every Change for the Final Report**:
   As edits are applied, keep a running list of each one — target locator, before → after values, tool used, and the reason. Phase 10 requires this as a detailed changelog table in the final output.

---

### Route B: Flutter Apps via MT Manager MCP (blutter output only)

**No extraction, no radare2, no apktool, no signer jar.** blutter supplies the annotated Dart AOT assembly; MT Manager patches `libapp.so` **in place inside the APK** with the native assembler (`mt_apk_native_patch_instructions`) and repacks + signs it (`mt_apk_build`). The only path to ask the user for is the blutter `out` directory — the `libs` folder and the decoded APK folder are obsolete.

#### Phase 8: Flutter — blutter Output to Patched APK

**Step 0 — Take the blutter `out` path (the only input)**
Ask for it; never guess or fabricate it. Validate before anything else:
```bash
python scripts/flutter_apk_pipeline.py check <out>    # needs asm/ + pp.txt
python scripts/flutter_apk_pipeline.py info  <out>    # libraries, function count, address range
```
Missing `asm/` or `pp.txt` → not a blutter output, ask again. If the user has not run blutter yet, hand them the two commands (extract libs for blutter only; the APK itself is never decompiled):
```bash
python scripts/flutter_apk_pipeline.py libs <app.apk>     # -> <app>_libs/libapp.so + libflutter.so
python3 blutter.py <app>_libs <out>                       # user runs this; Android arm64 only
```

**Step 1 — Build the address plan**
```bash
python scripts/flutter_apk_pipeline.py plan <out> --strings          # keyword sweep + pool URLs/keys
python scripts/flutter_apk_pipeline.py find <out> "isPremium|isActive|entitlement"
python scripts/flutter_apk_pipeline.py plan <out> --any --json plan.json   # every function + MCP args
```
Each blutter function carries `// ** addr: 0x...` — the **ELF virtual address inside `libapp.so`** (blutter disassembles at base 0). No conversion needed: feed it to the MCP as `addressKind="virtual"`. The JSON plan ships ready-made `mt_apk_native_disassemble` argument blocks per candidate.

**Step 2 — Open the workspace and inspect the lib**
```json
// mt_apk_workspace_open — mt://current-apk if the app is already open in MT
{ "path": "mt://current-apk", "temporary": false }
// mt_apk_native_inspect — confirm AArch64 and that the entry exists ("" = base view)
{ "workspaceId": "<workspaceId>", "editSessionId": "", "locator": "zip_entry:lib/arm64-v8a/libapp.so" }
```

**Step 3 — Create the edit session FIRST, then read the bytes in it**
`expectedHex` is a stale-view guard that must come from the same session and locator you are about to patch — a base-workspace (`editSessionId=""`) read can mismatch. Order:
1. `mt_apk_session_create(workspaceId=...)` → `editSessionId`.
2. `mt_apk_native_map_address(workspaceId=..., editSessionId=..., locator="zip_entry:lib/arm64-v8a/libapp.so", addressKind="virtual", address="0x<blutter addr>")` → require `found=true`, `mapping.isLoaded=true` **and** `mapping.isExecutable=true`; note `mapping.fileOffset`.
3. `mt_apk_native_disassemble(editSessionId=..., addressKind="virtual", address="0x<addr>", instructionMode="auto", maxBytes=64, maxInstructions=16)` → copy the byte column into `expectedHex`.

**Step 4 — Patch with the assembler**
```json
{
  "workspaceId": "<workspaceId>", "editSessionId": "<editSessionId>",
  "locator": "zip_entry:lib/arm64-v8a/libapp.so",
  "addressKind": "virtual", "address": "0x1a2b3c", "instructionMode": "auto",
  "expectedHex": "<bytes from step 3>",
  "replacementAssembly": "add x0, x22, #0x20\nret",
  "paddingMode": "nop"
}
```
- **Equal-length only** — Dart AOT bakes absolute offsets into the heap image; never shift bytes. `paddingMode="nop"` fills a shorter replacement.
- Assembly is encoded at the effective virtual address, so `b`/`bl`/`adrp` re-encode correctly — do not hand-hex PC-relative instructions.
- Recipes: `nop` (kill a call/branch), `ret` (early return), `add x0, x22, #0x20` + `ret` (Dart `true`), `#0x30` (Dart `false`), `mov w0, #0` / `#1` (int). Boolean singleton layout is version-dependent — verify against a known-returning sibling function in the same snapshot first.
- Virtual mapping misses (`isLoaded=false`)? Run `python scripts/flutter_apk_pipeline.py map <out> --lib libapp.so` and patch with `addressKind="file_offset"`. `MISS` = wrong build pairing, not a patchable address.
- Strings/pool text: `mt_apk_native_patch_string` (in place, `paddingMode` `none`/`null_pad`/`space_pad`); raw fallback `mt_apk_patch_bytes`.

**Step 5 — Check, build, sign, verify**
1. `mt_apk_session_check(workspaceId=..., editSessionId=..., runBuildChecks=true)`.
2. `mt_apk_build(workspaceId=..., editSessionId=..., sign=true, outputPath="<abs or Home-relative>.apk")` — MT repacks and signs; no uber-apk-signer step exists. Pass `""` for the default `_mcp_<editSessionId>_sign.apk` name in Home.
3. Re-read the patched window: `mt_apk_read_bytes(locator, byteOffset=<patchedFileOffset>, maxBytes=16)` and compare with the `afterHex` the patch returned.
4. Uninstall-then-install for testing (new signature; **wipes app data** — say so first), then verify the actual gate: screen opens, paywall gone, pinned host accepted, no launch crash.
5. Crash on launch with a clean patch = native integrity check over `libapp.so`; find the hash/CRC comparison (`native_strings` / smali search for the lib name) and neutralize it too.

*Full guide — Dart AOT internals, base-0 address model, patch recipes, failure table — in [references/flutter-reverse-engineering.md](references/flutter-reverse-engineering.md).*

---

### Route C: React Native Apps via Local Pipeline (No MT Manager)

**Do not use the MT Manager MCP server for Hermes bundle work.** Dex only wraps the RN runtime — the business logic (API clients, feature gates, paywalls) is **Hermes bytecode (HBC)** in `assets/index.android.bundle`, disassembled and patched locally. The lifecycle runs through the bundled script [`scripts/rn_hbc_pipeline.py`](scripts/rn_hbc_pipeline.py) (stdlib-only Python 3) plus the **Kirlif HBC-Tool fork** of hbctool (pip's hbctool 0.1.5 only supports HBC ≤ 76; current RN ships v96+). The MT Manager tools remain valid for the Dex wrapper — e.g. the Phase 6 ad/tracker SDK sweep still applies to it.

#### Phase 9: React Native Decompile, Patch and Rebuild Pipeline (Hermes)

**Step 1 — Recon**: `rn_hbc_pipeline.py pull <package>` resolves `adb shell pm path` and pulls `base.apk` plus every split; `adb shell dumpsys package <pkg>` for `versionName`/`dataDir`. Play split installs (~9 MB) vs sideloaded monoliths (~60 MB) differ in size by design — not bloat.

**Step 2 — Extract the bundle** (record size + sha256; the baseline for every later comparison):
```bash
python scripts/rn_hbc_pipeline.py extract base.apk      # -o bundle.hbc
```
The script verifies the Hermes magic (`C6 1F BC 03 C1 03 19 1F`) and prints the HBC version. No magic → plain JS bundle → patch as text, skip the rest.

**Step 3 — Disassemble** (pass the Kirlif fork checkout via `--hbctool <dir>` or `HBCTOOL_DIR`; `check` reports availability):
```bash
python scripts/rn_hbc_pipeline.py disasm bundle.hbc out/
# out/instruction.hasm (EDITABLE), out/metadata.json + out/string.json (NEVER edit)
```
`string.json` is the bundle's recon surface — every URL, endpoint, and flag name.

**Step 4 — Find the gate**: grep `string.json` for gate tokens (`is_paid`, `isLocked`, `locked`, `Premium`, `Subscribe`, `storyLocked`, `isPremiumContent`, …); grep `instruction.hasm` for those string ids to locate the renderer; map the lock flag register (a single register set from the gate string, consumed by `JmpFalse`/`JmpTrue`); confirm the renderer is unique (patch a second detail screen too).

**Step 5 — Prove the gate is client-side**: fetch a premium article's page — if the HTML contains the full body (plus an inline "subscribe" block), the server ships everything and the app only paints over it → patch the client. If the API truncates the body → no client patch can recover it; pivot to the WebView fallback.

**Step 6 — Patch, same-size only**: never change instruction length (jump offsets are relative to the instruction start; insertions shift every relative jump). The workhorse: `LoadConstTrue Reg8:N` → `LoadConstFalse Reg8:N` (2 bytes → 2 bytes). Verify the hasm diff is exactly the lines you intended.

**Step 7 — Round-trip proof** (mandatory, on the unmodified hasm first):
```bash
python scripts/rn_hbc_pipeline.py roundtrip bundle.hbc out/ --patched-hasm out_patched/
```
Assembles the unmodified hasm back to HBC, re-disassembles, diffs (line-identical modulo CRLF) and hash-compares (byte-identical) against the original bundle — only then assembles the patched hasm and diffs it against the baseline: exactly your edited lines, and 1 changed byte per single-instruction patch in the binary diff. A failed baseline means the toolchain does not round-trip this HBC version — fix the toolchain, never ship the patch.

**Step 8 — Repackage**: replace the bundle **STORED/uncompressed** (Hermes mmaps it), preserving entry order and compression types, then zipalign + apksigner with a debug key, then verify the bundle inside the signed APK hashes to the patched bundle:
```bash
python scripts/rn_hbc_pipeline.py repack base.apk bundle_patched.hbc
python scripts/rn_hbc_pipeline.py sign base_repacked.apk
python scripts/rn_hbc_pipeline.py verify-apk base_repacked-aligned-signed.apk bundle_patched.hbc
```

**Step 9 — Install + runtime test**: uninstall the Play build first (signature mismatch; **wipes app data — warn the user**), `adb install`, then open a premium article **from the in-app list** (not a deep link — deep links can take the WebView path). Pass criteria: full body, no fade overlay, no locked card, no "Continue Reading With Premium Access", audio/live-blog sections present.

**Fallbacks**: still gated → the article routed to the WebView; patch the routing config function (`isNativeArticleDetailScreen` / `app_Detail_Screen` keys in `string.json`) to unconditionally return `true`, or point the WebView at the article URL. Truncated body → server-side gating; patch the WebView `baseUrl`. Launch crash with a rejected bundle → integrity check; spoof the `sourceHash` in `metadata.json`.

*Full guide — HBC format notes, gate-mapping recipe, same-size patch rules, fallbacks, gotchas — in [references/react-native-reverse-engineering.md](references/react-native-reverse-engineering.md).*

---

### Phase 10: Structured Reporting

Deliver reverse engineering findings in two tiers — plus a **mandatory modification changelog** whenever the APK or any of its binaries was changed:

#### Modification Changelog Table (Mandatory When Any Change Was Made)
Whenever any modification was applied — Smali/code edits (`mt_apk_edit_text`), SDK neutralization stubs and manifest component disables (Phase 6), native instruction or string patches (`mt_apk_native_patch_instructions` / `mt_apk_native_patch_string`, including every Flutter `libapp.so` patch), resource edits (`mt_apk_resource_edit` / `mt_apk_resource_add`), raw byte patches (`mt_apk_patch_bytes`), Hermes `instruction.hasm` patches (Route C), or manifest tweaks — the **final message to the user must contain a detailed table of every change and why it was made**. This is a required deliverable, not an intermediate note: the session is not complete until this table appears in the final output alongside the findings tables.

One row per atomic change:

| # | Target (File / Class / Address) | Change Type | Before → After | Why (Rationale) | Verified By |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `dex_method:Lcom/example/license/LicenseCheck;->isValid()Z` | Smali edit (`mt_apk_edit_text`) | `const/4 v0, 0x0` → `const/4 v0, 0x1` | Force `isValid()` to return `true` so the patched build runs without the server-side license check | `mt_apk_session_check` passed; re-read of smali confirms the edit |
| 2 | `zip_entry:lib/arm64-v8a/libapp.so` @ virtual `0x1a2b40` | Native patch (`mt_apk_native_patch_instructions`, `paddingMode=nop`) | `bl 0x1a2c10` (`_LicenseValidator@validate`) → `nop` (equal-length, 4 bytes) | Skip the Dart AOT license gate invoked at startup; NOP keeps snapshot offsets stable | patch returned `afterHex` matching the re-read via `mt_apk_read_bytes`; rebuilt + signed APK launches trial features |
| 3 | `res/values/strings.xml` → `server_host` | Resource edit (`mt_apk_resource_edit`) | `https://prod.example.com` → `https://staging.example.com` | Redirect API traffic to the staging environment for safe testing | Re-read of resource confirms new value; rebuilt APK contacts staging host |
| 4 | `assets/index.android.bundle` → `instruction.hasm`, detail-renderer function | Hermes hasm edit (`rn_hbc_pipeline.py` round-trip + repack) | `LoadConstTrue Reg8:9` → `LoadConstFalse Reg8:9` (2 bytes → 2 bytes) | Flip the `is_paid` gate register so the detail renderer takes the unlocked branch; same-size patch keeps every relative jump valid | `roundtrip` diff shows exactly this line; binary diff = 1 byte; patched article renders fully |

Changelog rules:
- **One row per atomic change.** Never summarize multiple edits into a single row ("various smali edits" is unacceptable).
- **Why must give the reasoning, not restate the what**: "bypass license validation so the app starts offline", not "changed 0x0 to 0x1".
- **Before → After shows concrete original and new values** (instruction, string, resource entry, or byte range) so the user can audit or replay the patch elsewhere.
- **Include reverted or abandoned attempts**, marked as such in *Why* (e.g. "attempted `wa ret`, reverted — broke subsequent initialization"). The user needs to know what was tried.
- **Omit the table entirely when nothing was modified** — it applies only to sessions that changed the APK or its binaries.

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

- [Ads & Trackers Kit](references/ads-and-trackers/README.md) — SDK registry (50+ ad/tracker/consent SDKs with stub targets), smali stub catalog, consent reject-all injection, detection patterns. *Ported from the trackers-and-ads fork.*
- [API Extraction Patterns](references/api-extraction-patterns.md) — Exact search patterns for Retrofit, OkHttp, Ktor, Volley, headers, and tokens.
- [Call Flow Analysis](references/call-flow-analysis.md) — Tracing UI-to-network call graphs using `mt_apk_dex_xref`.
- [Native Reverse Engineering](references/native-reverse-engineering.md) — ELF inspection, JNI enumeration, disassembly, CFG, and binary patching.
- [Flutter Reverse Engineering](references/flutter-reverse-engineering.md) — Dart AOT snapshot internals, blutter output navigation, base-0 address model, and patching `libapp.so` in place with the MT Manager MCP native assembler.
- [React Native Reverse Engineering](references/react-native-reverse-engineering.md) — Hermes bytecode (HBC) format, hbctool/Kirlif toolchain, gate mapping in `instruction.hasm`, same-size patching with a mandatory round-trip proof, and bundle repack/sign.
- [RevenueCat Patching](references/revenuecat-patching.md) — Reaching the place to patch subscription gates: `CustomerInfo`/`PurchaserInfo`, `getEntitlements()`, `isActive()`, smali regex, obfuscation keyword `activeEntitlements:`, Java + Flutter worked examples.
- [Regex Batch Blocking](references/ads-and-trackers/regex-batch-blocking.md) — TDOhex three-rule smali regex board (void → `nop`, boolean → `const/4 0x0`, ad host → `127.0.0.1`) for a fast first pass across 30+ ad/tracker SDKs.
- [PairIP Google Protection](references/pairip-google-protection.md) — LuckyPatcher custom patch + smali stubs to disable `com.pairip.SignatureCheck.verifyIntegrity` and `LicenseClientV3.onActivityCreate` (`return-void`).
- [MT Manager Available Tools](references/available-tools.md) — Comprehensive reference table of all 67 MT Manager MCP tools and parameters.
