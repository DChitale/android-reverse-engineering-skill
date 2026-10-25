# API Extraction Patterns with MT Manager MCP

This guide details patterns and queries for finding HTTP API calls, endpoints, and authentication configurations inside Android APKs using the **MT Manager MCP** tools.

---

## 1. Fast Reconnaissance & Overview Search

Start with a high-level scan using `mt_apk_search` to find candidate API endpoints, URLs, and network clients:

```json
{
  "target": "overview",
  "query": "https://",
  "queryType": "literal",
  "caseSensitive": false,
  "matchMode": "contains",
  "prefix": "",
  "limit": 50,
  "snippetMaxChars": 240,
  "editSessionId": ""
}
```

Other high-signal overview queries:
- `"http://"`
- `"/api/"`
- `"/v1/"` or `"/v2/"`
- `".com/"`

For any match, examine `data.hits[i].locator` to identify the owning DEX class, method, or resource file.

---

## 2. Retrofit Analysis

Retrofit declares HTTP endpoints via method annotations on interface classes.

### Smali Annotation Queries

Use `mt_apk_search` with `target="smali"` to search for Retrofit HTTP method annotations:

| Target Pattern | Smali Descriptor Query |
| :--- | :--- |
| **GET Requests** | `Lretrofit2/http/GET;` |
| **POST Requests** | `Lretrofit2/http/POST;` |
| **PUT Requests** | `Lretrofit2/http/PUT;` |
| **DELETE Requests** | `Lretrofit2/http/DELETE;` |
| **PATCH Requests** | `Lretrofit2/http/PATCH;` |
| **Custom Headers** | `Lretrofit2/http/Headers;` |
| **Base URL Setup** | `baseUrl` or `Lretrofit2/Retrofit$Builder;->baseUrl` |

### Inspecting Retrofit Interfaces

Once a Retrofit interface class locator is discovered (e.g. `dex_class:Lcom/example/api/ApiService;`):

1. **Read Class Outline**:
   Call `mt_apk_dex_read_class_outline(locator="dex_class:Lcom/example/api/ApiService;")` to see all declared endpoint methods and their signatures without downloading massive text.
2. **Read Interface Method Smali**:
   Call `mt_apk_read_text(locator="dex_method:Lcom/example/api/ApiService;->getUser(Ljava/lang/String;)Lretrofit2/Call;")` to read the exact path annotation:
   ```smali
   .annotation runtime Lretrofit2/http/GET;
       value = "users/{id}"
   .end annotation
   ```

---

## 3. OkHttp & URL Builders

Apps using OkHttp directly construct requests via `Request.Builder` and `HttpUrl.Builder`.

### Search Queries in Smali

Search via `mt_apk_search(target="smali", ...)`:

- **Request Builder**: `Lokhttp3/Request$Builder;->url` or `Lokhttp3/Request$Builder;->post`
- **URL Builder**: `Lokhttp3/HttpUrl$Builder;->addPathSegment` or `addQueryParameter`
- **Interceptors (Auth / Logging)**: `Lokhttp3/Interceptor;` or `addInterceptor`
- **Client Execution**: `Lokhttp3/Call;->execute` or `enqueue`

### Tracing Auth Headers in OkHttp Interceptors

Authentication tokens (`Bearer`, `Authorization`, API keys) are typically injected via an `Interceptor`.
1. Search for: `mt_apk_search(target="smali", query="Authorization")` or query `header("Authorization"`
2. Read the interceptor method's Smali via `mt_apk_read_text` to understand token retrieval (e.g., SharedPreferences, Keystore, or memory cache).

---

## 4. Ktor & Kotlin Multiplatform

Ktor client calls are common in modern Kotlin apps.

### Search Patterns in Smali

- **HTTP Client**: `Lio/ktor/client/HttpClient;`
- **HTTP Methods**: `Lio/ktor/client/request/BuildersKt;->get` or `BuildersKt;->post`
- **URL Configuration**: `Lio/ktor/client/request/HttpRequestBuilder;->url`
- **Headers**: `Lio/ktor/http/HttpHeaders;->getAuthorization`

---

## 5. Volley & Legacy HTTP Clients

- **Volley Request**: `Lcom/android/volley/Request;`
- **String Request**: `Lcom/android/volley/toolbox/StringRequest;`
- **Json Request**: `Lcom/android/volley/toolbox/JsonObjectRequest;`
- **HttpURLConnection**: `Ljava/net/HttpURLConnection;->setRequestMethod`

---

## 6. Extracting Constants from `BuildConfig`

`BuildConfig` classes frequently store base URLs, API environment hosts, and feature flags.

1. Search for `BuildConfig` classes:
   ```json
   {
     "target": "smali",
     "query": "BuildConfig",
     "queryType": "literal",
     "caseSensitive": false,
     "matchMode": "contains",
     "prefix": "",
     "limit": 50,
     "snippetMaxChars": 240,
     "editSessionId": ""
   }
   ```
2. Read the class Smali with `mt_apk_read_text` to extract `static final` strings such as `BASE_URL`, `SERVER_HOST`, `API_KEY`.

---

## 7. Documentation Format

Deliver discovered endpoints in two standardized tiers:

### Tier 1: Flat Inventory Table (Comprehensive)
Provide one line for every discovered API endpoint:

| Host | Method | Path | Auth Type | Source Locator |
| :--- | :--- | :--- | :--- | :--- |
| `https://api.example.com` | `GET` | `/v1/users/{id}` | Bearer Token | `dex_method:Lcom/example/api/UserApi;->getUser` |
| `https://api.example.com` | `POST` | `/v1/auth/login` | None (Public) | `dex_method:Lcom/example/api/AuthApi;->login` |
| `https://telemetry.example.com` | `POST` | `/events` | Custom API-Key | `dex_method:Lcom/example/tracker/Analytics;->send` |

### Tier 2: Per-Endpoint Deep Dive (Key Flows)
For critical endpoints (Authentication, Payment, Order creation, Sensitive logic):

```markdown
### `POST /v1/auth/login`

- **Source Method**: `dex_method:Lcom/example/api/AuthApi;->login(Lcom/example/model/LoginReq;)Lretrofit2/Call;`
- **Base URL**: `https://api.example.com`
- **Headers**: `Content-Type: application/json`, `X-App-Version: 2.4.0`
- **Request Body Fields**:
  - `username` (String)
  - `password` (String)
  - `device_fingerprint` (String)
- **Response Type**: `Lcom/example/model/LoginResponse;`
- **Call Chain**: `LoginActivity$onCreate$1 -> LoginViewModel.submitLogin -> AuthRepository.login -> AuthApi.login`
```

If the session modified the APK (Dex/Smali, resources, native libraries, or `libapp.so`), the final output must additionally include the mandatory **Modification Changelog Table** defined in Phase 8 of the SKILL — one row per change with Target, Change Type, Before → After, Why, and how it was Verified.
