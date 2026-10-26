# Disabling (pairip) Google Protection — Custom Patch

Source: TDOHEX Official Repository — "Custom Patch for Disabling (pairip)Google Protection".

PairIP (`com.pairip.*`) is Play's signature-VM / integrity protection. A rebuilt + re-signed APK normally fails under it. This LuckyPatcher custom patch stubs the two entry methods so the integrity check is bypassed for the patched build.

## Patch snippet (LuckyPatcher custom patch format)

```
[BEGIN]
[use_fake_modified_apk_archive]
[CLASSES]
{"class name":"Lcom/pairip/SignatureCheck;"}
{"method name":"verifyIntegrity"}
{"return type":"V"}
{"replaced":"0E 00"}
{"class name":"Lcom/pairip/licensecheck3/LicenseClientV3;"}
{"method name":"onActivityCreate"}
{"return type":"V"}
{"replaced":"0E 00"}
[END]
```

`0E 00` = `return-void` (smali `return-void`). Stubs `verifyIntegrity` and `LicenseClientV3.onActivityCreate` to no-ops.

## How to use (LuckyPatcher)

1. Download/install LuckyPatcher.
2. Create a new `.txt` file named after the target package (e.g. `com.example.app.txt`).
3. Paste the snippet above. Append other patches between `[BEGIN]` and `[END]` if needed.
4. Save and move the `.txt` to LuckyPatcher's `CustomPatches` path.
5. In LuckyPatcher select the target app → "Menu of Patches" → "CustomPatch-applied APK" → "Rebuild The App".
6. After patching: "Go to file" → "Uninstall and install".

## Notes

- If `LicenseClientV3` is not present in the target, LuckyPatcher shows a red alert — safe to ignore.
- This is a LuckyPatcher workflow, not an MT Manager edit-session workflow. For MT Manager route, the equivalent is stubbing `com/pairip/SignatureCheck.verifyIntegrity` and `com/pairip/licensecheck3/LicenseClientV3.onActivityCreate` to `return-void` in smali, then rebuild+sign.
- Still warn the user: defeating PairIP may violate the app's EULA and Play Integrity will fail on the rebuilt APK.