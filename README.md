# Android Reverse Engineering Skill — MT Manager MCP

An agentic skill for reverse engineering Android applications (APK/XAPK), analyzing Smali/Dex bytecode, tracing HTTP API endpoints, reverse engineering native ELF (`.so`) libraries, and applying verified patches using the **MT Manager MCP Server**.

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
| **In-Place Patching & Building** | Staged copy-on-write edit sessions, Smali modification, instruction-level assembly patching, Dex checks, and signing. | `mt_apk_session_create`, `mt_apk_native_patch_instructions`, `mt_apk_build` |

---

## Requirements

- **MT Manager MCP Server**: Configured and active in your AI agent environment.
- No local Java JDK, jadx, or dex2jar installations are required — all operations are performed directly via the MCP server.

---

## Repository Structure

```
android-reverse-engineering-skill/
├── README.md                      # Overview & capabilities
├── SKILL.md                       # Core reverse engineering instructions & workflow
└── references/
    ├── api-extraction-patterns.md  # MT Manager MCP search queries for HTTP clients
    ├── call-flow-analysis.md      # Bytecode cross-reference & call tracing recipes
    └── native-reverse-engineering.md # ELF inspection, disassembly, CFG & patching
```

---

## References & Guides

- [API Extraction Patterns](references/api-extraction-patterns.md) — Retrofit, OkHttp, Ktor, Volley, and header extraction.
- [Call Flow Analysis](references/call-flow-analysis.md) — UI-to-network tracing with `mt_apk_dex_xref`.
- [Native Reverse Engineering](references/native-reverse-engineering.md) — Native `.so` analysis, disassembly, and assembly patching.
