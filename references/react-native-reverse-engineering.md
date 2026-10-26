# React Native (Hermes Bytecode) Reverse Engineering

Analyzing and patching **React Native** applications. An RN APK keeps almost no app logic in Dex — the JavaScript/TypeScript is compiled by Metro into `assets/index.android.bundle`. With Hermes enabled (default since RN 0.70), that bundle is **Hermes bytecode (HBC)** executed by `libhermes.so`; Dex only holds the RN runtime, native modules, and a thin `MainApplication` launcher. The real logic — API clients, feature gates, paywalls, telemetry flags — lives in the HBC bundle.

**How to recognize it:** Hermes bytecode starts with the magic bytes `C6 1F BC 03 C1 03 19 1F` (uint64 little-endian `0x1F1903C103BC1FC6`), followed by the bytecode version as a little-endian uint32 (observed versions: 74/76 on old RN, 84–90 on RN 0.70–0.72, 96+ on newer releases). If the bundle does **not** start with that magic, it is **plain JavaScript** (Hermes disabled or a dev build) — patch the JS directly with text tools; skip disassembly entirely.

**Sources for this guide:**

- Kirlif/HBC-Tool — hbctool fork with Hermes bytecode v89–99 support: <https://github.com/Kirlif/HBC-Tool>
- bongtrop/hbctool — upstream hbctool (pip 0.1.5 stops at v76, newer master at ~v89): <https://github.com/bongtrop/hbctool> (see issues [#48](https://github.com/bongtrop/hbctool/issues/48) and [#51](https://github.com/bongtrop/hbctool/issues/51) for the version-support discussion)
- P1sec/hermes-dec — independent Hermes disassembler/decompiler (disasm only, no re-assembly): <https://github.com/P1sec/hermes_dec>
- Pilfer/hermes_rs — dependency-free Rust Hermes disassembler: <https://github.com/Pilfer/hermes_rs>
- facebook/hermes — engine source; the authoritative format reference is `lib/BCGen/HBC/BytecodeFileFormat.h`: <https://github.com/facebook/hermes>

---

## 1. Toolchain (one-time setup)

- **hbctool — the Kirlif fork, not pip's.** `pip install hbctool` gives 0.1.5, which only supports HBC ≤ 76 and **asserts on anything newer** (e.g. v96/v98 bundles from current RN releases). Clone [Kirlif/HBC-Tool](https://github.com/Kirlif/HBC-Tool) to a directory and run it through the `PYTHONPATH` shim — no install step needed:

  ```bash
  PYTHONPATH=<fork-dir> python -c "import sys; sys.argv=['hbctool','disasm','bundle.hbc','out/']; import hbctool; hbctool.main()"
  # asm is the mirror: sys.argv=['hbctool','asm','out/','bundle_patched.hbc']
  ```

  The pipeline script ([`scripts/rn_hbc_pipeline.py`](../scripts/rn_hbc_pipeline.py)) wraps this — pass the fork checkout via `--hbctool <dir>` or the `HBCTOOL_DIR` env var.
- **zipalign + apksigner** from Android build-tools (`apksigner` is a `.bat` on Windows); **keytool** from a JDK; **adb** from platform-tools. The script auto-detects all of them (`ANDROID_HOME` / `ANDROID_SDK_ROOT` / `PATH`).
- Match the tool to the HBC version: function headers changed format across versions ("N symbols" vs "N numbers, M non-pointers"), so a toolchain that assembles one version cleanly may not parse another.

## 2. Recon

```bash
adb shell pm path <package>          # one line per APK: base.apk + splits
adb shell dumpsys package <package>  # versionName, dataDir, split vs monolithic
adb pull <path-from-pm-path> .
```

- Pull **every** path `pm path` lists — Play installs are split, but the Hermes bundle always lives in `base.apk`; the `config.*.apk` splits carry ABI libs and resources.
- Size is not bloat: a Play split install downloads ~9 MB while a sideloaded monolithic APK of the same app is ~60 MB — that is normal.
- Note `versionName` and `dataDir` from `dumpsys` for the report; a sideloaded reinstall over a Play install is impossible (signature mismatch) and will wipe `dataDir` — warn the user.

## 3. Extract the bundle

```bash
unzip -p base.apk assets/index.android.bundle > bundle.hbc
# or: python scripts/rn_hbc_pipeline.py extract base.apk
```

Record the **size and sha256** — this is the baseline for every later comparison. The script prints both and checks the Hermes magic/version up front.

## 4. Disassemble

```bash
python scripts/rn_hbc_pipeline.py disasm bundle.hbc out/
# equivalent: hbctool disasm bundle.hbc out/
```

Output:

| File | Content | Editable? |
| :--- | :--- | :--- |
| `instruction.hasm` | Per-function bytecode, one line per instruction | **Yes — the only file you may edit** |
| `metadata.json` | Bytecode/version metadata (incl. the `sourceHash`) | **No** |
| `string.json` | The string table, indexed by id | **No** |

Changing string or metadata content shifts offsets and corrupts the bundle; only patch instructions. (Exception: the `sourceHash` spoof in §11.)

## 5. Find the gate

`string.json` is the recon surface for the whole bundle — it contains every URL, endpoint, config key, and flag name (the HBC equivalent of blutter's `pp.txt` for Flutter).

1. **Grep `string.json` for gate tokens.** Paywall: `is_paid`, `isLocked`, `locked`, `Premium`, `Subscribe`, `storyLocked`, `detailPremium`, `isPremiumContent`. Generic feature gates: `isAdmin`, `isPro`, `is_subscribed`, `trial`, `entitled`, `feature_enabled`.
2. **Grep `instruction.hasm` for those string ids** — string references appear inline (e.g. `GetById ... 'is_paid'`). The hits cluster in the renderer function(s).
3. **Map the renderer function.** Read its head — `Function<>N(params, R registers, ...)` gives the parameter count and register file — then the lock computation. The lock flag is typically a **single register** (e.g. `r9` in the worked example) set from `is_paid` and consumed by `JmpFalse`/`JmpTrue` branches that gate the fade overlay, locked card, premium webview, audio player, live-blog sections, etc.
4. **Confirm the renderer is unique.** The gate string should appear in ~1 detail-screen renderer plus a few list-card mappers. If a second detail screen exists, patch it too.

## 6. Prove the gate is client-side (do not skip)

Fetch a premium article from the site in a browser (or `curl`) and check:

- Is the **full body present in the HTML** (possibly alongside an inline "premium content — subscribe to keep reading" block)? → The server ships everything and the app merely paints over it. **Patch the client flag** — the loop below works.
- Does the API **truncate the content** (body cut off server-side)? → No client patch can recover text that was never sent. **Pivot** to the WebView fallback in §11 (render the article URL directly).

```js
// in the page's devtools console:
window.isPremiumContent   // or grep the HTML for the body text + the premium notice
```

## 7. Patch — same-size only

> **Rule: never change instruction length.** Hermes jump offsets are relative to the **instruction start** (`pc0 + offset`); inserting or deleting bytes shifts every relative jump and corrupts control flow. Equal-size opcode swaps are safe.

The workhorse patch — flip a boolean gate (2 bytes → 2 bytes):

```text
LoadConstTrue  Reg8:9   →   LoadConstFalse Reg8:9
```

Procedure: edit the exact instruction in `instruction.hasm`, then verify the file diff is **exactly 1 line**. Before trusting any jump, resolve its target: offsets are relative to the instruction start, so an `Addr8` operand can reach further than it looks (a 5-byte `JmpTrue` can skip 2 instructions) — decode the fallthrough and confirm it lands on the merge point.

Other same-size options: invert the branch opcode itself (`JmpFalse` ↔ `JmpTrue`) when the flag is produced elsewhere, or retarget a jump's operand byte to merge-point. Anything requiring different operand widths is not a valid patch.

Worked example (livelaw.in): the detail renderer loads `is_paid` into `r9`; `LoadConstTrue Reg8:9` → `LoadConstFalse Reg8:9` makes every gated section render unlocked.

## 8. Verify the toolchain round-trips (before assembling the patch)

Do this ladder **on the unmodified hasm first** — it proves hbctool reassembles this exact bytecode version losslessly:

```bash
python scripts/rn_hbc_pipeline.py roundtrip bundle.hbc out/ --patched-hasm out_patched/
```

1. Assemble the **unpatched** hasm → HBC; re-disassemble it; diff against the original hasm → must be **line-identical** (modulo CRLF).
2. Hash-compare the round-tripped HBC against the original bundle → must be **byte-identical**.
3. Only then assemble the **patched** hasm; re-disassemble and diff against the unpatched round-trip → must be **exactly the line(s) you changed**.
4. Binary-diff the two HBCs → for the single-instruction patch, **1 byte at a single offset**.

If step 1–2 already diverge, the toolchain does not round-trip your HBC version — fix the toolchain, never ship a patch on top of a lossy assembler.

## 9. Repackage

```bash
python scripts/rn_hbc_pipeline.py repack base.apk bundle_patched.hbc
python scripts/rn_hbc_pipeline.py sign base_repacked.apk
python scripts/rn_hbc_pipeline.py verify-apk base_repacked-aligned-signed.apk bundle_patched.hbc
```

- Replace `assets/index.android.bundle` **keeping it STORED / uncompressed** — Hermes memory-maps the bundle; compressing it forces a copy (and breaks mmap-based loads). Preserve the APK's **entry order and compression types** for everything else.
- `zipalign -p -f 4`, then **sign with apksigner** (a debug key is fine; the Play key is impossible to obtain). zipalign first — apksigner preserves alignment, jarsigner does not.
- Split installs: re-sign **every** split with the same debug key and install with `adb install-multiple`, or install the patched `base.apk` alone and fall back to multiple if the device complains about missing ABI/config splits.
- Finally verify the bundle **inside the signed APK** hashes to your patched bundle (the `verify-apk` subcommand).

## 10. Install + runtime test

1. **Uninstall first** (signature mismatch vs the Play install) — this **wipes app data**; warn the user.
2. `adb install patched.apk`, launch, and open a premium article **from the in-app list** — not a deep link; deep links can take the WebView path and mask the result.
3. Pass criteria: full body visible, no fade overlay, no locked card, no "Continue Reading With Premium Access" strip, audio player and live-blog sections present.

## 11. Fallbacks

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| Still gated after the flag patch | The article routed to the WebView (`isNativeArticleDetailScreen` / `app_Detail_Screen` config keys in `string.json`) | Patch that config function to unconditionally return `true` (the "function 7440 pattern" — find the equivalent by grepping the config keys; function numbers are build-specific) or route the WebView at the article URL |
| Body arrives truncated | Server-side gating (§6 said so) | Patch the WebView `baseUrl` constant, or swap the renderer to load the `livelaw.in`-style article page directly |
| Patched build crashes on launch / bundle rejected | Integrity check on the bundle hash | Strip or spoof the `sourceHash` in `metadata.json` to match expectations (worked without touching it in the livelaw case; only touch it if the app verifies) |

## 12. Gotchas

- **Signed operands exist**: `UInt8:S` (signed byte) operands — account for them in size math.
- **Doubles are hex-encoded** in this fork's hasm output (`Double:0ad7a3703d70a3d7`-style), not decimal.
- **Function headers differ across HBC versions** ("N symbols" vs "N numbers, M non-pointers") — match the tool to the bytecode version.
- **Jump targets are instruction-start relative**: an `Addr8` jump can legitimately skip 2 instructions; resolve targets before trusting a patch (§7).
- **Verify polarity before flipping a constant.** `JmpFalse` branches when the register holds false — which branch that reaches (locked vs unlocked rendering) depends on how the flag is computed. Decode the jump target and fallthrough (§7) and confirm the patched value steers execution to the *unlocked* path; if the polarity is inverted, use the branch-opcode swap instead.
- **Play split vs sideloaded monolith** differ in size by ~7× — normal (§2), don't chase it.

## 13. Ads and trackers in RN apps

Native ad/analytics SDKs (AdMob, AppsFlyer, …) still live in the Dex wrapper — run the full Phase 6 registry sweep on it. JS-level tracking (fetch calls to telemetry endpoints, in-app consent prompts driven from the bundle) is found the same way as gates: grep `string.json` for the domains and flag names, then follow the references in `instruction.hasm`. The same-size patch rules of §7 apply unchanged.
