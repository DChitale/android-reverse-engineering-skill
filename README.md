# Android Reverse Engineering Skill — MT Manager MCP

An agentic skill for reverse engineering Android applications (APK/XAPK), analyzing Smali/Dex bytecode, tracing HTTP API endpoints, reverse engineering native ELF (`.so`) libraries, reverse engineering Flutter apps (Dart AOT `libapp.so`), and applying verified patches using the **MT Manager MCP Server**.

---

## Capabilities

| Capability | Description | MT Manager MCP Engine |
| :--- | :--- | :--- |
| **Instant Workspace Triage** | Opens APKs into indexed workspaces without manual decompilation or unpacking. Reads full signature & certificate profiles. | `mt_apk_workspace_open`, `mt_apk_read_signature` |
| **Framework Fingerprinting** | Identifies Flutter, React Native, Cordova, Xamarin, or native Java/Kotlin in seconds via entry examination. | `mt_apk_list` |
| **Decoded Manifest & Outlines** | Reads decoded `AndroidManifest.xml` and class definitions directly without downloading whole source dumps. | `mt_apk_read_text`, `mt_apk_dex_read_class_outline` |
| **API Endpoint Extraction** | Extracts Retrofit annotations, OkHttp builders, Ktor routes, URL constants, and `BuildConfig` variables. | `mt_apk_search`, `mt_apk_read_text` |
| **Bytecode Call Flow Tracing** | Resolves inbound method, field, and class cross-references across inheritance hierarchies. | `mt_apk_dex_xref` (`dispatch`, `slot`, `exact`) |
| **Native ELF Analysis** | Inspects architectures, enumerates JNI exports, disassembles machine code, and builds control flow graphs (CFGs). | `mt_apk_native_inspect`, `mt_apk_native_disassemble`, `mt_apk_native_analyze_control_flow` |
| **Flutter (Dart AOT) Analysis** | Fingerprints the Dart version, navigates blutter-decompiled output, and patches `libapp.so` with radare2. Requires the user to supply the blutter output path. | `mt_zip_extract`, `mt_apk_patch_bytes` + [blutter](https://github.com/worawit/blutter) + [r2flutter](https://github.com/radareorg/r2flutter) + radare2 |
| **In-Place Patching & Building** | Staged copy-on-write edit sessions, Smali modification, instruction-level assembly patching, Dex checks, and signing. | `mt_apk_session_create`, `mt_apk_native_patch_instructions`, `mt_apk_build` |

---

## Requirements

- **MT Manager MCP Server**: Configured and active in your AI agent environment.
- **Flutter targets**: [blutter](https://github.com/worawit/blutter) output (run by the user) and [radare2](https://r2wiki.readthedocs.io/en/latest/home/misc/cheatsheet/) for editing `libapp.so`.
- No local Java JDK, jadx, or dex2jar installations are required — all operations are performed directly via the MCP server.

---

## Repository Structure

```
android-reverse-engineering-skill/
├── README.md                      # Overview & capabilities
├── SKILL.md                       # Core reverse engineering instructions & workflow
└── references/
    ├── api-extraction-patterns.md  # MT Manager MCP search queries for HTTP clients
    ├── available-tools.md          # Reference table of all 57 MT Manager MCP tools
    ├── call-flow-analysis.md      # Bytecode cross-reference & call tracing recipes
    ├── flutter-reverse-engineering.md # Dart AOT snapshot analysis, blutter & radare2
    └── native-reverse-engineering.md # ELF inspection, disassembly, CFG & patching
```

**Installation:** copy this repo's `SKILL.md` and `references/` into `~/.agents/skills/apk-reverse-engineering-mt-manager/` (user-level, all projects) or `<project>/.agents/skills/apk-reverse-engineering-mt-manager/` (project-level) so agents auto-discover the skill.

---

## References & Guides

- [API Extraction Patterns](references/api-extraction-patterns.md) — Retrofit, OkHttp, Ktor, Volley, and header extraction.
- [Call Flow Analysis](references/call-flow-analysis.md) — UI-to-network tracing with `mt_apk_dex_xref`.
- [Native Reverse Engineering](references/native-reverse-engineering.md) — Native `.so` analysis, disassembly, and assembly patching.
- [Flutter Reverse Engineering](references/flutter-reverse-engineering.md) — Dart AOT snapshot internals, blutter output navigation, and editing `libapp.so` with radare2.
- [MT Manager Available Tools](references/available-tools.md) — Reference table of all 57 MT Manager MCP tools and parameters.
