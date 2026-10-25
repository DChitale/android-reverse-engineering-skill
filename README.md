# Android Reverse Engineering Skill — Java Route (MT Manager MCP) & Flutter Route (Local Pipeline)

An agentic skill for reverse engineering and cracking Android applications (APK/XAPK). The skill asks the user for the app type up front and routes to one of two toolchains:

- **Java/Kotlin apps → Route A (MT Manager MCP Server)**: Smali/Dex analysis, HTTP API endpoint extraction, UI-to-network call-flow tracing, native ELF (`.so`) analysis, and verified patch/rebuild — with radare2 for native lib patching (the user extracts the specific lib, r2 patches it, the patch is replayed via an edit session).
- **Flutter apps → Route B (local pipeline, no MT Manager)**: a bundled Python script drives apktool decompile/rebuild (auto-installed from [iBotPeaches/Apktool](https://github.com/iBotPeaches/Apktool/releases)), blutter + radare2 for Dart AOT `libapp.so` patching, and [uber-apk-signer](https://favr.dev/opensource/uber-apk-signer/) for zipalign + signing (auto-downloaded from [patrickfav/uber-apk-signer](https://github.com/patrickfav/uber-apk-signer/releases)).

---

## Capabilities

| Capability | Description | MT Manager MCP Engine |
| :--- | :--- | :--- |
| **Instant Workspace Triage** | Opens APKs into indexed workspaces without manual decompilation or unpacking. Reads full signature & certificate profiles. | `mt_apk_workspace_open`, `mt_apk_read_signature` |
| **Framework Fingerprinting** | Identifies Flutter, React Native, Cordova, Xamarin, or native Java/Kotlin in seconds via entry examination. | `mt_apk_list` |
| **Decoded Manifest & Outlines** | Reads decoded `AndroidManifest.xml` and class definitions directly without downloading whole source dumps. | `mt_apk_read_text`, `mt_apk_dex_read_class_outline` |
| **API Endpoint Extraction** | Extracts Retrofit annotations, OkHttp builders, Ktor routes, URL constants, and `BuildConfig` variables. | `mt_apk_search`, `mt_apk_read_text` |
| **Bytecode Call Flow Tracing** | Resolves inbound method, field, and class cross-references across inheritance hierarchies. | `mt_apk_dex_xref` (`dispatch`, `slot`, `exact`) |
| **Native ELF Analysis & Lib Patching** | Inspects architectures, enumerates JNI exports, disassembles machine code, and builds control flow graphs (CFGs). When a lib needs patching, the user extracts it and radare2 applies equal-length patches, replayed into the APK via an edit session. | `mt_apk_native_inspect`, `mt_apk_native_disassemble`, `mt_apk_native_analyze_control_flow`, `mt_apk_patch_bytes` + radare2 |
| **Flutter (Dart AOT) Analysis & Patching** | Local pipeline with no MCP: apktool decompile/rebuild (auto-installed), blutter-decompiled output navigation, radare2 patching of `libapp.so`, uber-apk-signer signing (jar path requested, auto-downloaded). | `scripts/flutter_apk_pipeline.py` + [blutter](https://github.com/worawit/blutter) + [r2flutter](https://github.com/radareorg/r2flutter) + radare2 |
| **In-Place Patching & Building** | Staged copy-on-write edit sessions, Smali modification, instruction-level assembly patching, Dex checks, and signing. | `mt_apk_session_create`, `mt_apk_native_patch_instructions`, `mt_apk_build` |

---

## Requirements

- **Route A (Java/Kotlin)**: MT Manager MCP Server configured and active in your AI agent environment. No local Java JDK, jadx, or dex2jar installations required.
- **Route B (Flutter)**: Python 3, Java 8+ (for apktool and uber-apk-signer), and [radare2](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/). apktool and uber-apk-signer are auto-downloaded by the pipeline script when missing. [blutter](https://github.com/worawit/blutter) output is run by the user externally.

---

## Repository Structure

```
android-reverse-engineering-skill/
├── README.md                      # Overview & capabilities
├── SKILL.md                       # Core reverse engineering instructions & workflow
├── scripts/
│   └── flutter_apk_pipeline.py    # Route B: apktool decompile/rebuild + uber-apk-signer
└── references/
    ├── api-extraction-patterns.md  # MT Manager MCP search queries for HTTP clients
    ├── available-tools.md          # Reference table of all 57 MT Manager MCP tools
    ├── call-flow-analysis.md      # Bytecode cross-reference & call tracing recipes
    ├── flutter-reverse-engineering.md # Dart AOT snapshot analysis, blutter & radare2
    └── native-reverse-engineering.md # ELF inspection, disassembly, CFG & patching
```

**Installation:** copy this repo's `SKILL.md`, `references/`, and `scripts/` into `~/.agents/skills/apk-reverse-engineering-mt-manager/` (user-level, all projects) or `<project>/.agents/skills/apk-reverse-engineering-mt-manager/` (project-level) so agents auto-discover the skill.

---

## References & Guides

- [API Extraction Patterns](references/api-extraction-patterns.md) — Retrofit, OkHttp, Ktor, Volley, and header extraction.
- [Call Flow Analysis](references/call-flow-analysis.md) — UI-to-network tracing with `mt_apk_dex_xref`.
- [Native Reverse Engineering](references/native-reverse-engineering.md) — Native `.so` analysis, disassembly, and assembly patching.
- [Flutter Reverse Engineering](references/flutter-reverse-engineering.md) — Dart AOT snapshot internals, blutter output navigation, and editing `libapp.so` with radare2.
- [MT Manager Available Tools](references/available-tools.md) — Reference table of all 57 MT Manager MCP tools and parameters.
