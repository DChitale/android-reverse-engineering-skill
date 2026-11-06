# Ads & Trackers — Regex Batch Blocking (TDOhex board)

A three-rule **regex batch replace** pass that kills ad/tracker calls across 30+ SDKs in one sweep. It is the fastest first move on a Java/Kotlin target: broad, mechanical, and cheap to revert per-method — but blunt, so it runs **before** the registry-driven stub pass (Phase 6), not instead of it.

**Provenance:** TDOhex patch set — <https://t.me/TDOhex/383>. Patterns reproduced verbatim; anchors and caveats below are ours.

Applied with MT Manager's in-app *Regex batch replace* over the smali tree, or through `mt_apk_search` → `mt_apk_edit_text` per match inside an MCP edit session.

---

## 1. The three rules

| Rule | Matches | Replace | Effect |
| :--- | :--- | :--- | :--- |
| **VoidSearch** | `invoke-*` on an ad-SDK path, method returns `V`, name matches load/show/cache/init/report/url… | `nop` | The SDK call never executes. Argument setup before it survives as dead code (harmless). |
| **BooleanSearch** | same call shape returning `Z`, followed by `move-result <reg>` | `const/4 $9, 0x0` | Every "is an ad loaded / shown / available / cached" answer becomes **false**, and the `move-result` is replaced in place — register stays defined, verifier stays happy. |
| **StringSearch** | quoted ad/tracker host literals | `"127.0.0.1"` | DNS/HTTPS goes to loopback: requests fail fast and quietly instead of resolving to a live ad server. |

### Why the anchors are shaped that way

- **Negative lookahead** `(?!.*(close|Deactiv|Destroy|Dismiss|Disabl|error|player|remov|expir|fail|hide|skip|stop|Throw))` — keeps lifecycle, teardown, error-report and player paths out of the blast radius. Without it you nop the callback that *stops* an ad, and the UI deadlocks behind an overlay.
- **`\(.*\)V` only** on the void rule — a `nop` over a non-void call would orphan the `move-result` that follows and the Dex verifier rejects the class. This is why the boolean case is a separate rule: it replaces **both** lines, capturing the register as `$9`.
- **`\n\n\s{4}` in the boolean rule** — standard smali indents `move-result` with four spaces after a blank line. Reproduced from MT's dump format; reformatted smali breaks the match (fail-safe: no match, no edit).
- **Path alternation, not class list** — matching `/(ads|admob|applovin|ironsource|…)/` catches SDK internals plus mediation adapters without enumerating every class.
- **`.*Request)` alternation** — covers the generated request-builder classes that most SDKs route everything through.

---

## 2. Apply it

### Option A — MT Manager in-app batch (fastest)

1. Open the APK in MT Manager's APK editor (full smali decode).
2. Regex batch replace → paste **VoidSearch** / **VoidReplace**, run, then **BooleanSearch** / **BooleanReplace** (`const/4 $9, 0x0` keeps the capture-group reference), then **StringSearch** / **StringReplace** (`"127.0.0.1"`).
3. Rebuild and sign.

### Option B — MCP edit session (auditable, per-match)

1. `mt_apk_workspace_open` → `mt_apk_session_create`.
2. **Count before you cut.** For each rule:
   ```jsonc
   { "workspaceId": "<workspaceId>", "editSessionId": "", "target": "smali",
     "queryType": "regex", "query": "<search pattern>", "limit": 50 }
   ```
   Read the hit list. Hits whose class name is obviously app code (not SDK) are false positives — the path alternation matches any package segment named `ads`.
3. Apply per match with `mt_apk_edit_text` (`replace_match`) using the `targetVersion` from the read, or delete the whole method with `mt_apk_delete_target` when the entire method is ad plumbing.
4. `mt_apk_session_check(runBuildChecks=true)` — the Dex verifier is the referee. Any class it rejects, revert that one method and move on; a single rejected class fails the build.
5. `mt_apk_build(sign=true, outputPath=...)`.

**Order matters:** void pass → boolean pass → string pass. The string rule rewrites constants the other two may still be matching on; strings last keeps the code pass deterministic.

---

## 3. Precedence with the registry kit

| Situation | Use |
| :--- | :--- |
| Broad first pass, unknown SDK mix, time-boxed | This board (all three rules) |
| SDK identified and active, needs clean removal | Registry `targets` stubs — see [neutralization-guide.md](neutralization-guide.md) |
| Regex pass missed the SDK's entry point (`getInstance()` singleton, mediation adapter) | Registry depth 1–2 stubs |
| Consent framework (UMP / IAB TCF) | [consent-neutralization.md](consent-neutralization.md) reject-all injection — the regex board does nothing here |
| Flutter / React Native target | Not applicable — no smali. See the Flutter/RN routes in `SKILL.md` |

Log both passes separately in the Phase 10 changelog: the regex rows are bulk (one row per rule + hit count + sample locators), the registry rows are per-method.

---

## 4. Caveats — read before running the string rule

- **The string alternation is not ad-only.** It includes infrastructure hosts: `analytics`, `appmetrica`, `appsflyer`, `mixpanel`, `umeng`, `comscore`, `crashlytics`, `googletagmanager`, `gstatic`, `googleapis.*.ad-*`, `cloudfront`, `mapbox`, `media.net`, `metrics.`, `dummy`. Loopback-ing these breaks map tiles, font/CDN loading, crash reporting, deferred deep links and login flows. Either accept the breakage deliberately (privacy-max build) or prune the alternation to ad networks only before running.
- **Reflection and JNI escape it.** Unity Ads, IronSource adapters and AppLovin's `com.applovin.impl.*` reach code through reflection; there is no matching `invoke` line. Those need the registry pass or native patching.
- **In-house / WebView ads survive.** App-owned wrappers serving MRAID or "house" creatives are outside the package alternation — detect them per Phase 6 (`in_house_wrapper` flags, or the app-owned package driving the ad SDK calls).
- **Stubbing can null-crash.** `nop`-ing an initializer while another path still calls `getInstance()`-style accessors yields NPEs. The boolean rule helps (callers see `false` and bail), which is why it is not optional.
- **Signature loss.** Rebuilt APK is re-signed: Play Integrity fails, no Play updates over it, app data is wiped on install. EULA/ToS exposure is the operator's call.
- **Obfuscation.** R8 renames SDK classes but usually leaves the package roots in the path — if every rule returns zero hits, check `mt_apk_search(target="smali", query="Lcom/", queryType="literal")` output for the actual roots.

---

## 5. Verify

1. Build clean (`session_check` green) and install.
2. `adb logcat | findstr /i "adcolony admob applovin appodeal chartboost doubleclick inmobi ironsource mopub unityads vungle"` — after the pass, no SDK banners, no `AdRequest` retries.
3. Exercise 5–6 screens, including one that previously showed a rewarded/interstitial ad, and one that gates content behind "watch an ad".
4. Confirm the two things the string rule may have broken: map/tile rendering and crash reporting (if kept).
5. Log the rows: rule id, hit count, sample class locators, and every method reverted after a verifier rejection.

---

## 6. Patterns (verbatim)

```regex
VoidSearch:
(invoke(?!.*(close|Deactiv|Destroy|Dismiss|Disabl|error|player|remov|expir|fail|hide|skip|stop|Throw)).*/(adcolony|admob|ads|adsdk|aerserv|appbrain|applovin|appodeal|appodealx|appsflyer|bytedance/sdk/openadsdk|chartboost|flurry|fyber|hyprmx|inmobi|ironsource|mbrg|mbridge|mintegral|moat|mobfox|mobilefuse|mopub|my/target|ogury|Omid|onesignal|presage|smaato|smartadserver|snap/adkit|snap/appadskit|startapp|taboola|tapjoy|tappx|vungle)/.*>(request.*|(.*(activat|Banner|build|Event|exec|header|html|initAd|initi|JavaScript|Interstitial|load|log|MetaData|metri|Native|onAd|propert|report|response|Rewarded|show|trac|url|(fetch|refresh|render|video)Ad).*)|.*Request)\(.*\)V)
```

```regex
BooleanSearch:
(invoke(?!.*(close|Deactiv|Destroy|Dismiss|Disabl|error|player|remov|expir|fail|hide|skip|stop|Throw)).*/(adcolony|admob|ads|adsdk|aerserv|appbrain|applovin|appodeal|appodealx|appsflyer|bytedance/sdk/openadsdk|chartboost|flurry|fyber|hyprmx|inmobi|ironsource|mbrg|mbridge|mintegral|moat|mobfox|mobilefuse|mopub|my/target|ogury|Omid|onesignal|presage|smaato|smartadserver|snap/adkit|snap/appadskit|startapp|taboola|tapjoy|tappx|vungle)/.*>(request.*|(.*(activat|Banner|build|Event|exec|header|html|initAd|initi|JavaScript|Interstitial|load|log|MetaData|metri|Native|(can|get|is|has|was)Ad|propert|report|response|Rewarded|show|trac|url|(fetch|refresh|render|video)Ad).*)|.*Request)\(.*\)Z\n\n\s{4})move-result\s([pv]\d+)
```

```regex
StringSearch:
"(http.*|//.*)(61\.145\.124\.238|/2mdn\.net|-ads\.|\.5rocks\.io|\.ad\.|\.adadapted|\.admitad\.|\.admost\.|\.ads\.|\.aerserv\.|\.airpush\.|\.batmobil\.|\.chartboost\.|\.cloudmobi\.|\.conviva\.|\.dov-e\.com|\.fyber\.|\.mng-ads\|\.mydas\.|\.predic\.|\.talkingdata\.|\.tapdaq\.|\.tele\.fm|\.unity3d\.|\.unity\.|\.wapstart\.|\.xdrig\.|\.zapr\.|\/ad\.|\/ads|a4\.tl|accengage|ad4push|ad4screen|ad-mail|ad\..*_logging|ad\.api\.kaffnet\.|ad\.cauly\.co\.|adbuddiz|adc3-launch|adcolony|adfurikun|adincube|adinformation|adkmob|admax\.|admixer|admob|admost|ads\.mdotm\.|adsafeprotected|adservice|adsmogo|adsrvr|adswizz|adtag|adtech\.de|advert|adwhirl|adz\.wattpad\.|alimama\.|alta\.eqmob\.|amazon-.*ads|amazon\..*ads|amobee|analytics|anvato|appboy|appbrain|applovin|applvn|appmetrica|appnext|appodeal|appsdt|appsflyer|apsalar|avocarrot|axonix|banners-slb\.mobile\.yandex\.net|banners\.mobile\.yandex\.net|brightcove\.|burstly|cauly|cloudfront|cmcm\.|com\.google\.android\.gms\.ads\.identifier\.service\.START|comscore|contextual\.media\.net|crashlytics|crispwireless|criteo\.|dmtry\.|doubleclick|duapps|dummy|flurry|fwmrm|gad|getads|gimbal|glispa|google\.com\/dfp|googleAds|googleads|googleapis\..*\.ad-.*|googlesyndication|googletagmanager|greystripe|gstatic|heyzap|hyprmx|iasds01|inmobi|inneractive|instreamatic|integralads|jumptag|jwpcdn|jwpltx|jwpsrv|kochava|localytics|madnet|mapbox|mc\.yandex\.ru|media\.net|metrics\.|millennialmedia|mixpanel|mng-ads\.com|moat\.|moatads|mobclix|mobfox|mobpowertech|moodpresence|mopub|native_ads|nativex\.|nexage\.|ooyala|openx\.|pagead|pingstart|prebid|presage\.io|pubmatic|pubnative|rayjump|saspreview|scorecardresearch|smaato|smartadserver|sponsorpay|startappservice|startup\.mobile\.yandex\.net|statistics\.videofarm\.daum\.net|supersonicads|taboola|tapas|tapjoy|tapylitics|target\.my\.com|teads\.|umeng|unityads|vungle|zucks).*"
```

Replacements: **Void** → `nop` · **Boolean** → `const/4 $9, 0x0` · **String** → `"127.0.0.1"`.
