# RevenueCat Subscription Bypass — Reaching the Place to Patch

Source: TDOHEX Official Repository (articles: "How to Reach Place to Patch Trough revenuecat", "6th Example…", "Practical Examples…", "Flutter Examples…").

RevenueCat grants "pro" access when `EntitlementInfo.isActive()` is true inside a `CustomerInfo`/`PurchaserInfo` object. To patch an app you do **not** need to defeat RevenueCat's server — you find the call site in the app where the entitlement check result is consumed and flip it.

## 1. Java / Kotlin apps (MT Manager route)

### How the gate looks

- Subscription status is read from `CustomerInfo` (also called `PurchaserInfo`) and `EntitlementInfo`.
- `"pro"` is granted when the user has an active entitlement.
- `CustomerInfo` is empty until a purchase is made / transactions synced.

```java
// Check if the specified entitlement is active
if (customerInfo.getEntitlements().get(<my_entitlement_identifier>).isActive()) {
    // Grant user "pro" access
    // <-- reach this code flow and apply the patch here
}
```

### Locators

- Class: `Lcom/revenuecat/purchases/CustomerInfo;`  (older builds: `Lcom/revenuecat/purchases/PurchaserInfo;`)
- Method to search: `getEntitlements()`
- Search regex (smali):

```
invoke-virtual \{([pv]\d+)\}, Lcom/revenuecat/purchases/(CustomerInfo|PurchaserInfo);->getEntitlements\(\)Lcom/revenuecat/purchases/EntitlementInfos;([\w\W])*?move-result-object ([pv]\d+)
```

### Obfuscated builds

When names are obfuscated, search for the surviving keyword:

```
activeEntitlements:
```

### Patch point

Patch the boolean result consumed after `isActive()` (or the branch that follows `getEntitlements()`), e.g. force the entitlement check to return `true` / skip the gated block. Verify with `mt_apk_session_check` before rebuild.

### Worked examples (Java/Kotlin)

- **Fishbrain** (`com.fishbrain.app`, v10.166.2) — state held in a Kotlin `MutableStateFlow`; patch the flow emission.
- **FX Video Maker**, **Chemistry**, **VSCO**, **Zoomerang**, **AI Real Voice** — each unlocked through the same RevenueCat gate location.

## 2. Flutter apps (local pipeline, no MT Manager)

Use blutter to decompile `libapp.so`, then locate the RevenueCat Dart code by searching the blutter output for `CustomerInfo`, `getEntitlements`, `isActive`, `activeEntitlements`. Patch the Dart function / branch with radare2 per `references/flutter-reverse-engineering.md`.

Worked examples: **MuscleWiki**, **Liftbear**, **Glyf AI**, **Video Compressor (ShrinkVid)**. Tooling: `blutter-termux` (see `references/flutter-reverse-engineering.md` and the blutter-termux guide).

## 3. Documentation

- https://www.revenuecat.com/docs/making-purchases
- https://www.revenuecat.com/docs/customer-info#checking-if-a-user-is-subscribed
- https://www.revenuecat.com/docs/getting-started#-check-subscription-status
- https://www.revenuecat.com/docs/purchaserinfo#section-get-entitlement-information

## 4. Related site tutorials (video)

- Practical Examples to Reach Place to Patch Through revenuecat
- 6th Example to Reach Place to Patch Through revenuecat
- Flutter Examples to Reach Place to Patch Through revenuecat
- Video Tutorial on this method (linked from the Java article)