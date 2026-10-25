# Ads & Trackers: Detection and Neutralization Kit

Detection and neutralization knowledge for **ad SDKs**, **tracker/analytics SDKs**, and **consent frameworks** — covering 50+ SDKs (AdMob, Unity Ads, IronSource, AppLovin, Meta Audience Network, Vungle, Pangle, Mintegral, Firebase Analytics, Adjust, AppsFlyer, Mixpanel, Amplitude, Braze, CleverTap, AppMetrica, Crashlytics, Google UMP, and more).

> **Ported from the [trackers-and-ads fork](https://github.com/SimoneAvogadro/android-reverse-engineering-skill/tree/trackers-and-ads)** of this project (Apache-2.0). That fork implements the same techniques as shell/Python scripts over apktool/jadx-decoded trees; this skill runs the same playbook through the **MT Manager MCP server** (Java route) or the **apktool pipeline** (Flutter route) instead. The mapping:

| Fork step (script) | This skill's equivalent |
| :--- | :--- |
| `find-ads.sh` / `find-trackers.sh` <dir> | Sweep smali/manifest/resources with `mt_apk_search` + `mt_apk_read_text` using the registry's `packages`, marker classes, `manifest_names`, `domains`, `id_prefixes` (see Phase 6 of the SKILL) |
| `sdk-audit.sh --entrypoints` (active vs passive SDKs) | `mt_apk_dex_xref` on each SDK entry point to see whether app code (non-SDK packages) actually calls it |
| `registry-scan.py` <dir> | Read `registry/*.json` directly; match `packages` against `mt_apk_list(view="dex_classes")` output |
| `neutralize.sh --dry-run` | Present the planned stubs (from registry `targets` + `smali-patterns.md`) for user confirmation before creating any edit |
| `neutralize.sh` (apply) | `mt_apk_edit_text` on each target method (stub body) + manifest component `android:enabled="false"` via `mt_apk_edit_text` on `axml:AndroidManifest.xml` |
| `detect-protection.sh` | Manifest/smali markers: `com.pairip.*`, declared components missing from `dex_classes`, `com.google.android.vending.licensing` |
| `detect-adwrapper.sh` | In-house wrapper flags in the registry (`in_house_wrapper: true`); otherwise an unknown app-owned package driving ad SDK calls |
| `decode-apk.sh` / `rebuild-apk.sh` | Route B pipeline: `scripts/flutter_apk_pipeline.py decompile/rebuild/sign` |
| `neutralize-manifest.json` (patch log) | The Phase 9 **Modification Changelog Table** in the final output |

## Contents

| File | What it holds |
| :--- | :--- |
| `registry/*.json` | **The single source of SDK knowledge**: per-SDK `packages`, `targets` (entry_points / ad_operations / deep_patterns with class + method + signature + stub type), `manifest_components`, `detection` (marker classes, domains, ID prefixes, APIs), `in_house_wrapper` flags. `_schema.json` documents the format; `_audit-shared.json` holds cross-SDK tables (library roots, ad format tables, legacy flags). |
| `neutralization-guide.md` | Approach (stub > remove > block), return-type → stub mapping, singleton/`getInstance()` null pitfalls, manifest disable-vs-remove, multidex, R8 obfuscation, signature invalidation, legal notes. |
| `smali-patterns.md` | Complete smali stub catalog per SDK — read this before writing any stub. |
| `consent-neutralization.md` | Google UMP / IAB TCF v2.2 "reject-all" code injection: which `IABTCF_*` SharedPreferences keys to write, where to hook, caveats. |
| `registry-backlog.md` | Coverage gaps: detection-only entries (no `targets` yet: Segment, Flurry, TikTok Business, BIGO Ads, Kidoz, APM Insight), missing SDKs. |
| `tracker-init-patterns.md` | Init calls, event logging, user identification, consent APIs per tracker SDK. |
| `data-exfiltration-patterns.md` | Endpoint domains, proxy/relay patterns, batch upload shapes per tracker. |
| `tracker-sdk-catalog.md` / `ad-sdk-catalog.md` | Short per-SDK notes + Gradle coordinates. |
| `ad-format-patterns.md` | Banner / interstitial / rewarded / native / app-open load-show lifecycles. |
| `mediation-patterns.md` | Mediators vs mediated networks, adapters, waterfall vs bidding, active vs passive SDKs. |

## Reading the registry

Every entry is literal-matched (no regex). Example (`registry/google-admob.json`):

```json
{
  "sdk_id": "google-admob",
  "category": "ads",
  "packages": ["com.google.android.gms.ads"],
  "targets": {
    "entry_points": [
      { "class": "com.google.android.gms.ads.MobileAds",
        "methods": [
          { "name": "initialize", "signature": "(Landroid/content/Context;)V",
            "stub": "return-void", "note": "Main SDK init — disables entire ad pipeline" }
        ] }
    ],
    "ad_operations": [ "..." ],
    "deep_patterns": [ "..." ]
  },
  "manifest_components": [ "com.google.android.gms.ads.AdActivity" ]
}
```

- **Depth 1** (default, safest) = `entry_points` only; **Depth 2** adds `ad_operations`; **Depth 3** adds `deep_patterns` (version-dependent, most aggressive).
- Entries **without `targets`** are detection-only — report them but do not attempt stubs (`registry-backlog.md` lists the gaps).
- The optional `detection` object (marker classes, `domains`, `id_prefixes` like `ca-app-pub-`) is evidence for *finding* the SDK, not for stubbing.

**Obfuscation caveat:** R8/ProGuard renames SDK classes, so registry matching fails on obfuscated builds. Endpoint URLs, app-ID prefixes, and manifest `meta-data` names survive obfuscation and are the fallback identification path (see `detection` data and `data-exfiltration-patterns.md`).
