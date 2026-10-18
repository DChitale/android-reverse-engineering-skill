# Call Flow Analysis with MT Manager MCP

Techniques for tracing execution flows from Android UI components and lifecycle entry points down to business logic and network requests using **MT Manager MCP**.

---

## 1. Entry Point Identification via Decoded Manifest

Every Android execution chain begins with a component declared in `AndroidManifest.xml`.

### Read the Decoded Manifest

Call `mt_apk_read_text` with locator `"axml:AndroidManifest.xml"`:

```json
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

### Key Elements to Extract:
- **Application Class**: `android:name` on `<application>` (executes first via `onCreate()`).
- **Main Launcher Activity**: Contains `<action android:name="android.intent.action.MAIN"/>` and `<category android:name="android.intent.category.LAUNCHER"/>`.
- **Exported Activities & Deep Links**: Check for `<intent-filter>` with custom schemes (`https://` or custom protocol URI handlers).
- **Background Services & Receivers**: `<service>`, `<receiver>`, and `<provider>`.

---

## 2. Bytecode Cross-Reference Tracing with `mt_apk_dex_xref`

Unlike decompiled source folders where text searching (`grep`) can be slow and noisy, **MT Manager MCP** provides direct bytecode reference analysis via `mt_apk_dex_xref`.

### Method Cross-References

```json
{
  "workspaceId": "<workspaceId>",
  "editSessionId": "",
  "locator": "dex_method:Lcom/example/api/AuthApi;->login(Ljava/lang/String;Ljava/lang/String;)V",
  "methodResolution": "dispatch",
  "limit": 50
}
```

#### Understanding `methodResolution`:
- **`dispatch`** *(Recommended)*: Finds all calls that can reach the target method or interface implementation across inheritance and interface implementations.
- **`exact`**: Strict bytecode equality matching the exact `MethodReference` opcode target.
- **`slot`**: Finds the visible override family across subclasses.

### Field & Class Cross-References

- **`dex_field:`**: Finds all instructions reading or writing a specific field (`methodResolution="not_applicable"`).
- **`dex_class:`**: Finds all instructions referencing a class type (`methodResolution="not_applicable"`).

---

## 3. Following the Android Call Hierarchy

A standard Android call flow follows this path:

```
Activity.onCreate() / Fragment.onViewCreated()
  │
  ▼ [View Binding / Synthetic Click Listener]
OnClickListener.onClick()
  │
  ▼ [Call ViewModel method]
ViewModel.submitRequest()
  │
  ▼ [Coroutine / RxJava / Background Thread]
Repository.fetchData()
  │
  ▼ [Retrofit / OkHttp]
ApiService.callEndpoint()
```

### Step-by-Step Tracing Technique:

1. **Find Caller of Network Method**:
   Call `mt_apk_dex_xref` on the API method:
   ```
   refs[0].sourceLocator = "dex_method:Lcom/example/repo/UserRepository;->authenticate(...)V"
   ```
2. **Inspect Caller Implementation**:
   Call `mt_apk_read_text` on `refs[0].sourceLocator` to view the Smali instructions:
   - Identify parameter transformations, token inclusions, and encryption/hashing.
3. **Repeat Upwards**:
   Call `mt_apk_dex_xref` on `dex_method:Lcom/example/repo/UserRepository;->authenticate(...)V`:
   - Leads to `LoginViewModel.onLoginClick(...)`.
4. **Reach UI Component**:
   Call `mt_apk_dex_xref` on `LoginViewModel.onLoginClick(...)`:
   - Leads to `LoginActivity$initViews$1.onClick(...)` or Compose event handler.

---

## 4. Handling Obfuscation & Mangled Names (R8/ProGuard)

When classes are renamed to `a.b.c`, standard navigation breaks. Use bytecode anchors:

1. **String Anchors**:
   Hardcoded strings (such as `"/v1/auth"`, `"token"`, `"AES/CBC/PKCS5Padding"`) remain unchanged. Search via `mt_apk_search(target="smali", query="<string>")`.
2. **Library Signatures**:
   System and third-party SDK calls (e.g., `Landroid/widget/Button;->setOnClickListener`, `Lokhttp3/OkHttpClient;->newCall`) are preserved. Use them as xref pivot points.
3. **Kotlin Metadata Recovery**:
   Kotlin coroutines and state classes frequently preserve class names in `@kotlin/coroutines/jvm/internal/DebugMetadata` annotations. Search via `mt_apk_search(target="smali", query="DebugMetadata")`.

---

## 5. Dependency Injection & Asynchronous Chains

### Dagger / Hilt
- Injected classes implement factory classes ending in `_Factory` or `_MembersInjector`.
- Modules have methods annotated with `Ldagger/Provides;` or `Ldagger/Binds;`.
- Use `mt_apk_dex_xref` on the injected constructor to find where Dagger instantiates the repository/service.

### Kotlin Coroutines
- Coroutine lambdas compile to separate inner classes (e.g., `Class$method$1`).
- The asynchronous execution lives inside the `invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;` method of the generated continuation class.
- Read `invokeSuspend` with `mt_apk_read_text` to trace the actual asynchronous business logic.
