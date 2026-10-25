---
name: apk-reverse-engineering-mt-manager
description: Reverse engineer and crack Android apps via two toolchains, selected by asking the user for the app type up front. Java/Kotlin apps use the MT Manager MCP server for Dex/Smali inspection, HTTP API endpoint extraction (Retrofit, OkHttp, Ktor, Volley), UI-to-network call-flow tracing, native ELF (.so) disassembly, radare2 lib patching with verified patch/rebuild, and ad/tracker SDK detection & removal (stub AdMob, Unity, IronSource, Firebase Analytics, Adjust, AppsFlyer and 50+ more via the SDK registry). Flutter apps use a local Python pipeline with NO MT Manager — apktool decompile/rebuild (auto-installed), blutter + radare2 for Dart AOT libapp.so patching, and uber-apk-signer for signing. Use when the user wants to decompile, inspect, crack, reverse engineer, or patch Android packages, extract API endpoints, analyze native libraries, remove ads, remove trackers, strip telemetry, neutralize SDKs, or analyze/patch Flutter apps and libapp.so. 中文触发词：反编译APK、安卓逆向、提取API、分析安卓应用、反编译安卓、逆向工程、追踪调用链、提取接口、修改APK、破解APP、去广告、移除广告、去除追踪器、移除SDK、隐私分析、Flutter逆向、分析libapp.so、修改libapp.so、Dart快照分析
---

# Android Reverse Engineering — Java Route (MT Manager MCP) & Flutter Route (Local Pipeline)

Two toolchains, selected up front by asking the user which kind of app it is:

- **Java/Kotlin app** → **Route A**: the **MT Manager MCP Server** handles workspace triage, Dex/Smali inspection, API extraction, call-flow tracing, native ELF analysis, and verified patch/rebuild. Apps that require native lib patching: the user extracts the specific lib, radare2 patches it, and the patch is replayed through an MT Manager edit session. Ad/tracker SDK removal is built in (Phase 6).
- **Flutter app** → **Route B**: a local **Python pipeline** — apktool (decompile/rebuild, auto-installed), blutter + radare2 (Dart AOT `libapp.so` analysis/patching), uber-apk-signer (signing). **No MT Manager MCP for Flutter targets.**

---

## Quick Navigation

- [Phase 0: App Type Selection (Ask First)](#phase-0-app-type-selection-ask-first)
- **Route A — Java/Kotlin via MT Manager MCP**
  - [Phase 1: Workspace Setup and Signature Inspection](#phase-1-workspace-setup-and-signature-inspection)
  - [Phase 2: Manifest and Architecture Survey](#phase-2-manifest-and-architecture-survey)
  - [Phase 3: API and Network Endpoint Extraction](#phase-3-api-and-network-endpoint-extraction)
  - [Phase 4: Bytecode Call Flow and Cross-Reference Tracing](#phase-4-bytecode-call-flow-and-cross-reference-tracing)
  - [Phase 5: Native ELF (.so) Analysis and Lib Patching with radare2](#phase-5-native-elf-so-analysis-and-lib-patching-with-radare2)
  - [Phase 6: Ads and Tracker SDK Detection and Neutralization](#phase-6-ads-and-tracker-sdk-detection-and-neutralization)
  - [Phase 7: Modification, Patching and APK Rebuilding via Edit Sessions](#phase-7-modification-patching-and-apk-rebuilding-via-edit-sessions)
- **Route B — Flutter via local pipeline (no MT Manager)**
  - [Phase 8: Flutter Decompile, Patch and Rebuild Pipeline](#phase-8-flutter-decompile-patch-and-rebuild-pipeline)
- [Phase 9: Structured Reporting](#phase-9-structured-reporting)
- [References & Guides](#references--guides)

---

## Workflow

### Phase 0: App Type Selection (Ask First)

**Before touching any tool, ask the user which type of app it is:**

> "Is the target app a **Java/Kotlin** (native Android) app or a **Flutter** app?"

| Answer | Route |
| :--- | :--- |
| Java / Kotlin / "normal Android app" | **Route A** — Phases 1–7 (MT Manager MCP) |
| Flutter | **Route B** — Phase 8 (local apktool pipeline, no MT Manager) |

If the user is unsure, detect it locally (no MCP needed) by listing the APK's zip entries (`python -c "import zipfile; [print(n) for n in zipfile.ZipFile('target.apk').namelist()]"` or `unzip -l target.apk`):

| Marker Detected | Type | Route / Implication |
| :--- | :--- | :--- |
| `lib/*/libapp.so` + `libflutter.so`, or `assets/flutter_assets/` | **Flutter** | Route B — Dex only holds the thin `io.flutter` launcher; logic is in `libapp.so`. |
| `assets/index.android.bundle` | **React Native** | Route A for the wrapper; business logic is in the Hermes/JS bundle — extract and inspect separately. |
| `assets/www/index.html` | **Cordova / Capacitor** | Route A for the wrapper; inspect HTML/JS under `assets/www/`. |
| `assemblies/`, `libmonosgen*.so` | **Xamarin / .NET MAUI** | Route A; logic compiled into .NET DLL assemblies. |
| None of the above | **Native Java/Kotlin** | Route A — full Dex/Smali reverse engineering applies. |

Both routes finish at **Phase 9: Structured Reporting**.

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

#### Phase 5: Native ELF (.so) Analysis and Lib Patching with radare2

Some Java/Kotlin apps move license checks, cryptography, or anti-tamper logic into native libraries.

**Analysis:**
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

**When the lib actually needs patching (extract → r2 → replay):**
1. **Ask the user to extract that specific lib from the APK** — tell them the exact zip entry path (e.g. `lib/arm64-v8a/libnative.so`) and have them pull it out (MT Manager file extraction, or `unzip target.apk "lib/arm64-v8a/libnative.so" -d extracted/`). Patch a real file on disk; never blind-patch inside the APK.
2. **Patch the extracted lib with radare2**: keep a pristine copy (`cp libnative.so libnative.so.orig`), open with `r2 -w` (or `r2flutter -AAA` for Dart-style named analysis of ELF targets), apply **equal-length in-place overwrites only** (`wa nop` over a `bl`, `wa ret` for early return, `wx <hex>` for raw bytes), and verify with `radiff2 -C` that only the intended bytes changed.
3. **Replay the verified patch into the APK** through an MT Manager edit session: `mt_apk_patch_bytes` on the original `zip_entry:` locator using file offsets plus `expectedHex` from the pristine copy (stale-write guard), or `mt_apk_native_patch_instructions` with `addressKind="virtual"` for simple instruction overwrites.
4. **Check & build**: `mt_apk_session_check(workspaceId=..., editSessionId=..., runBuildChecks=true)` → `mt_apk_build(workspaceId=..., editSessionId=..., sign=true, outputName="output_patched.apk")`.

*See native instructions and examples in [references/native-reverse-engineering.md](references/native-reverse-engineering.md).*

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

**Step 2 — Neutralize (dry-run plan → edit session):**
Present the plan first: for each confirmed SDK, which methods get stubbed at which depth, and which manifest components get disabled. Only after user approval, open an edit session (Phase 7) and:
1. **Stub method bodies** per the registry `targets` using `mt_apk_read_text` + `mt_apk_edit_text` on each `dex_method:` locator — replace the body with the stub recipe for its return type (`return-void`, `const/4 v0, 0x0` + `return-object v0` for null, etc.; full catalog in `smali-patterns.md`):
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
- **Flutter apps**: ad/tracker SDKs are compiled into `libapp.so` — detect via `pp.txt`/`asm/` greps in the blutter output (domains, SDK keys); there are no smali stubs to make. Neutralization is r2 patching of the Dart functions or network-level blocking.

**Step 4 — Verify & report:** `mt_apk_session_check(runBuildChecks=true)` → `mt_apk_build(sign=true)` → every stubbed method and disabled component becomes a row in the Phase 9 Modification Changelog.

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
   As edits are applied, keep a running list of each one — target locator, before → after values, tool used, and the reason. Phase 9 requires this as a detailed changelog table in the final output.

---

### Route B: Flutter Apps via Local Pipeline (No MT Manager)

**Do not use the MT Manager MCP server for Flutter targets.** The whole APK lifecycle runs through the bundled script [`scripts/flutter_apk_pipeline.py`](scripts/flutter_apk_pipeline.py) (stdlib-only Python 3): apktool for decompile/rebuild, uber-apk-signer for zipalign + sign, with automatic tool installation.

#### Phase 8: Flutter Decompile, Patch and Rebuild Pipeline

**Step 1 — Decompile** (the script asks for the APK path when it is not given):
```bash
python scripts/flutter_apk_pipeline.py decompile <app.apk>
```
- Verifies **Java 8+** is available, then resolves apktool in order: `PATH` → `APKTOOL_JAR` env → `tools/apktool.jar`. If apktool is not installed, the latest release is auto-downloaded from [iBotPeaches/Apktool releases](https://github.com/iBotPeaches/Apktool/releases).
- Output: `<name>_decoded/` containing smali, decoded resources, and `lib/arm64-v8a/libapp.so` + `libflutter.so`.

**Step 2 — Analyze with blutter** (external, user-run):
Ask for the blutter `out` folder if the user has not provided one — never guess or fabricate it. `libs` defaults to `<name>_decoded/lib/arm64-v8a` from the decompile step. If the user has not run blutter yet:
`python3 blutter.py <name>_decoded/lib/arm64-v8a <out>` (Android arm64 only; blutter auto-detects the Dart version from `libflutter.so`). Validate: `out/` must contain `asm/` and `pp.txt`.

**Step 3 — Patch `libapp.so` with radare2**:
Grep `out/asm/` for `Class_method` symbols and `out/pp.txt` for URLs/tokens — function headers carry `addr: 0x...` virtual addresses inside `libapp.so`. Open the decoded lib with `r2 -w` (optionally `r2flutter -AAA` for named navigation) and patch with **equal-length in-place overwrites only** (`wa nop` over a `bl`, `wa ret` for early return, `wx <hex>`); never shift snapshot bytes. Verify with `radiff2 -C`.

**Step 4 — Rebuild the APK**:
```bash
python scripts/flutter_apk_pipeline.py rebuild <name>_decoded
```
Runs `apktool b` → produces `<name>_rebuilt.apk` next to the decoded folder.

**Step 5 — Sign with uber-apk-signer**:
```bash
python scripts/flutter_apk_pipeline.py sign <name>_rebuilt.apk
```
- The script **asks the user for the uber-apk-signer jar path first**; if it is not available, the latest release is auto-downloaded from [patrickfav/uber-apk-signer releases](https://github.com/patrickfav/uber-apk-signer/releases) ([project page](https://favr.dev/opensource/uber-apk-signer/)).
- Zipaligns and debug-signs in one pass → `<name>_rebuilt-aligned-signed.apk`.

Launcher-wrapper tweaks (rare for Flutter): edit smali/resources directly under `<name>_decoded/` before the rebuild.

*Full guide — snapshot format tables, codegen patterns, radare2 recipes — in [references/flutter-reverse-engineering.md](references/flutter-reverse-engineering.md).*

---

### Phase 9: Structured Reporting

Deliver reverse engineering findings in two tiers — plus a **mandatory modification changelog** whenever the APK or any of its binaries was changed:

#### Modification Changelog Table (Mandatory When Any Change Was Made)
Whenever any modification was applied — Smali/code edits (`mt_apk_edit_text` or direct edits in the apktool-decoded folder), SDK neutralization stubs and manifest component disables (Phase 6), native instruction or string patches (`mt_apk_native_patch_instructions` / `mt_apk_native_patch_string`), resource edits (`mt_apk_resource_edit` / `mt_apk_resource_add`), raw byte patches (`mt_apk_patch_bytes`), radare2 edits to `libapp.so` or to an extracted native lib, or manifest tweaks — the **final message to the user must contain a detailed table of every change and why it was made**. This is a required deliverable, not an intermediate note: the session is not complete until this table appears in the final output alongside the findings tables.

One row per atomic change:

| # | Target (File / Class / Address) | Change Type | Before → After | Why (Rationale) | Verified By |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `dex_method:Lcom/example/license/LicenseCheck;->isValid()Z` | Smali edit (`mt_apk_edit_text`) | `const/4 v0, 0x0` → `const/4 v0, 0x1` | Force `isValid()` to return `true` so the patched build runs without the server-side license check | `mt_apk_session_check` passed; re-read of smali confirms the edit |
| 2 | `lib/arm64-v8a/libapp.so` @ `0x1a2b40` | Native patch (radare2 `wa nop` on the decoded lib) | `bl 0x1a2c10` (`_LicenseValidator@validate`) → `nop` (equal-length, 4 bytes) | Skip the Dart AOT license gate invoked at startup; NOP keeps snapshot offsets stable | `radiff2 -C` shows only this hunk; rebuilt + signed APK launches trial features |
| 3 | `res/values/strings.xml` → `server_host` | Resource edit (`mt_apk_resource_edit`) | `https://prod.example.com` → `https://staging.example.com` | Redirect API traffic to the staging environment for safe testing | Re-read of resource confirms new value; rebuilt APK contacts staging host |

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
- [Flutter Reverse Engineering](references/flutter-reverse-engineering.md) — Dart AOT snapshot internals, manual assembly analysis, blutter output navigation, and editing `libapp.so` with radare2.
- [MT Manager Available Tools](references/available-tools.md) — Comprehensive reference table of all 57 MT Manager MCP tools and parameters.
