# OpenZeekr — CLOUD layer spec (rewrite reference)

Source of truth: `/home/user/openzeekr` (read-only audit). Files covered:
`core/.../net/*` (ApiClient, AccountLogin, Signing, OverseasSign, VinCrypto, Region, ZeekrConst, TspApi,
Interceptors, InboxAuthToken, SessionSignal, UpdateChecker), `core/.../net/model/Models.kt`,
`core/.../remote/*`, `core/.../push/*`, `app/.../push/*`, `core/.../config/*`, `secrets.example.json`,
`secrets.properties.example`, `core/src/test/**`. Callers in `app/` (App.kt heartbeat loop, UI param
builders) were consulted only where they define wire values.

No secret VALUES exist in the repo; everything secret is user-supplied (section 8). Non-secret app
constants that are verbatim in the stock APK (client ids, app codes, tenant codes) ARE reproduced here
because the wire format needs them.

---------------------------------------------------------------------------------------------------

## 0. Architecture in one paragraph

There are **four independent backends** with **four signing schemes**:

| # | Backend | Host (EU) | Auth / signing | Used for |
|---|---------|-----------|----------------|----------|
| A | **User-center (IDaaS)** | `https://gateway-pub-azure.zeekr.eu/zeekr-cuc-idaas/` | `DEFAULT_HEADERS` + **UC HMAC** (X-HMAC-*, key = `hmac_secret_key`) + `authorization: <ucToken>` after login | login steps 1–4, 4c |
| B | **TSP gateway** | `https://eu-snc-tsp-api-gw.zeekrlife.com/` | `LOGGED_IN_HEADERS` + `authorization: <TSP bearer>` + `x-vin: AES(VIN)` + **X-SIGNATURE** (HMAC-SHA256, key = `prod_secret`) | bearer login, vehicles, status, all remote control, charging, schedules, journeys, sharing, capabilities, heartbeat, sentry, DK |
| C | **Azure "overseas-app" + message-core** (same host as A) | `https://gateway-pub-azure.zeekr.eu/overseas-app/…`, `/zom-message-core/…` | **Overseas HMAC** (X-HMAC-*, key = `overseas_secret_key`) + static app headers + `Authorization: <azureToken>` (= ucToken) | inbox, vehicle config (paint/series), OTA, FCM push registration |
| D | **xchanger / ECARX DK backend** | `https://api-zk.ecloudeu.com` | **HF sign** (HMAC-SHA1, key = `xchanger_sign_secret`) + device headers | DK backend session (login step 4b) |

Plus GitHub Releases API (unauthenticated) for update checks.

Generic response envelope (A, B, C): `{ "code": String, "msg": String?, "message": String?, "success": Boolean, "sessionId": String?, "data": T }`. Success = `success == true` OR `code == "000000"`. Exceptions: xchanger `{code:1000, data, error:{code,message}}`; ecarx System-B `{code:Int 1000|200, …}`; message-core push `{code:200, msg:"success", data:{endpoint}}`.

---------------------------------------------------------------------------------------------------

## 1. Regions

### 1.1 Region catalog (`net/Region.kt`)

| code | displayName | TSP base (`baseUrl`) | Azure host (`azureHost`) | xchanger host | X-PROJECT-ID | default country | SNS region | extractorRegion (secret set) | verified flag |
|---|---|---|---|---|---|---|---|---|---|
| EU | Europe (EU) | `https://eu-snc-tsp-api-gw.zeekrlife.com` | `https://gateway-pub-azure.zeekr.eu` | `https://api-zk.ecloudeu.com` | `ZEEKR_EU` | `SE` | `eu-central-1` | `EU` | true |
| SEA | Australia + SEA | `https://sea-snc-tsp-api-gw.zeekrlife.com` | `https://gateway-pub-hw-em-sg.zeekrlife.com` | `https://api-zk.ecloudkr.com` | `ZEEKR_SEA` | `SG` | `ap-southeast-1` | `EM` | false (comment says a real SEA login was verified 2026-09-23) |
| LA | Latin America (LA / BR) | `https://la-snc-tsp-api-gw.zeekrlife.com` | `https://gateway-pub-hw-em-mx.zeekrlife.com` | `https://api-zk.ecloudeu.com` | `ZEEKR_LA` | `BR` | `us-east-1` | `EM` | true |
| ME | Middle East (ME) | `https://me-snc-tsp-api-gw.zeekrlife.com` | `https://gateway-pub-aws-em-ae.zeekrlife.com` | `https://api-zk.ecloudeu.com` (uncertain) | `ZEEKR_ME` | `AE` | `me-central-1` | `EM` | false |

`Region.byCode(code)` is case-insensitive, unknown/blank → EU. Picker order = EU, SEA, LA, ME.

### 1.2 Region-derived service paths (`SecretsConfig`)

| Service | Formula | EU | SEA | LA | ME |
|---|---|---|---|---|---|
| User-center base (`usercenterUrl`, trailing `/`) | `{azureHost}/{seg}/` | `zeekr-cuc-idaas` | `zeekr-cuc-idaas-sea` | `zeekr-cuc-idaas-la` | `zeekr-cuc-idaas-uae` |
| App-server (`appServerUrl`) | `{azureHost}/overseas-app/` | same all regions |
| Inbox (`inboxUrl`, no trailing `/`) | `{azureHost}/overseas-app/member/inbox` | same all regions |
| Message-core (`messageCoreUrl`, no trailing `/`) | `{azureHost}/{seg}` | `zom-message-core` | `sea-message-core` | `la-message-core` | `uae-message-core` |
| xchanger session (`xchangerSessionUrl`) | `{xchangerHost}/auth/account/session/secure?identity_type=zeekr` | | | | |

Only the EU usercenter segment and SEA's are confirmed; LA/ME segments are best-effort.

### 1.3 Per-region constants elsewhere

* xchanger `X-APP-ID` (`ZeekrConst.xchangerAppId`): `LA` → `7d46f4c500fa4e92bef2a92cd6aeebcd` (com.zeekr.global appid); every other region → `8bbb65c1c4a288a28152c36dfa792014`. (Lumping SEA onto the global id broke SEA login.)
* Secrets: the stock native lib distinguishes only **EU / EM / SEA** secret sets. `setRegion()` swaps only `hmac_access_key`, `hmac_secret_key`, `prod_secret` to the region's baked set (`NativeSecrets.*(extractorRegion)`), falling back to existing values when blank. All other secrets are shared across regions. Note SEA's `extractorRegion` is `EM` (TSP X-SIGNATURE uses EM set) while the SEA user-center HMAC keys are SEA-specific and user-entered.
* `countryCode` on region switch is overwritten only if it still equals the previous region's default (preserves a manual edit). After login step 3b the account's own ISO-2 country may override it (see 2.2).
* `ZeekrConst.projectId(regionCode)` (EU→ZEEKR_EU, LA→ZEEKR_LA, else ZEEKR_SEA) is **dead code** — the live value comes from `Region.projectId`. ME would disagree (ZEEKR_ME vs ZEEKR_SEA).
* After any region/base-URL change the Retrofit client must be rebuilt (`ApiClient.rebuild()` via `Deps.onEndpointChanged()`); Retrofit base URL is captured at build time.
* All host fields are user-overridable in Settings (advanced host overrides).

---------------------------------------------------------------------------------------------------

## 2. Authentication flow

### 2.1 Constants

`ZeekrConst.CLIENT_ID` (TSP OAuth client, a.k.a. App-Code) = `1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc`
`ZeekrConst.XCHANGER_CLIENT_ID` (2nd OAuth client, overseas Client-Id) = `1d1921ad4d314ab7b0042a2fe0f479c3`

**DEFAULT_HEADERS** (user-center; applied by `UcInterceptor` only if the request does not already carry the header):

```
accept-language: en-AU
app-authorization: 1003
app-code: 32816dbd-ff17-47b7-e250-5dae7d9f8cd4
appcode: eu-app
appid: TSP
appsecret: zeekr_tis
appversion: 1.4.1
call-source: android
client-id: 1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc
Content-Type: application/json; charset=UTF-8
country: {countryCode}
device-name: sdk_gphone64_x86_64
device-type: app
language: en
msgappid: 11002
msgclientid: 1003
registcountry: {countryCode}
tmp-tenant-code: 3300743799505195008
user-agent: Device/GoogleAppName/com.zeekr.globalAppVersion/1.4.1Platform/androidOSVersion/16Ditto/true
```
Then `authorization: {ucToken}` once step 2 succeeded (in-memory only within the login run), then the 5 UC-HMAC headers (§3.1). **Do not set Accept-Encoding manually** (OkHttp's transparent gzip must own it; SEA's WAF gzips everything). `execRoot` additionally gunzips if `Content-Encoding: gzip` reaches it (fallback).

Device identity spoofed everywhere: manufacturer/brand `google`, product `panther`, model `Pixel 7`, Android `16`, SDK `36`.

### 2.2 Login sequence (`AccountLogin.login()`)

Preconditions (fail before any network): `email` (trimmed) & `password` set; `hmac_access_key` & `hmac_secret_key` set; `prod_secret` set; `password_public_key` set. Let `UC = usercenterUrl`, `TSP = baseUrl + "/"`.

| Step | Call | Host / client | Request | Response used | Failure policy |
|---|---|---|---|---|---|
| 1 | `POST {UC}auth/checkUserV2` | user-center (UC HMAC) | `{"email":"<email>","checkType":"1"}` | envelope success only | **fatal**. Canary: validates HMAC before password is ever sent (avoid lockout). Code `9007` → "Account not found in this region". |
| 2 | `POST {UC}auth/loginByEmailEncrypt` | user-center | `{"code":"","codeId":"","email":"<email>","password":"<RSA b64>"}` | `data.tokenName` must == `"Authorization"`, `data.tokenValue` non-blank → **ucToken** (persisted as `azureToken`) | fatal. `9300`/`9301` = password rejected (SEA: maybe email-code required). |
| 3 | `POST {UC}user/info` | user-center, body `{}` | — | `data.userId` ?: `data.id` (fallback userId); `data.uuid` → **accountUuid / openId** (32-hex) | fatal |
| 3b | (local) | — | — | first 2-letter alpha value among `countryCode, country, nationCode, registCountry, registerCountry, nationality` in user/info → overrides `countryCode` (uppercased) | best-effort; field names are INFERRED (TODO 0.2.7) |
| 4 | `GET {UC}user/tspCode?tspClientId=1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc` | user-center | — | `data.code` → **tspCode** (one-time auth code) | fatal ("no tsp code") |
| 4b | `GET {UC}user/tspCode?tspClientId=1d1921ad4d314ab7b0042a2fe0f479c3` with header overrides `app-authorization: 1009`, `client-id: 1d1921ad4d314ab7b0042a2fe0f479c3` | user-center | — | `data.code` → **xchanger authCode** | best-effort (whole 4b) |
| 4b′ | `POST {xchangerHost}/auth/account/session/secure?identity_type=zeekr` | xchanger (HF sign, §3.4) | `{"authCode":"<code>"}` (compact) | root `code == "1000"` and `data` object → `data.clientId` → `xchangerClientId`, `data.accessToken` → `xchangerToken`; error in `error.code/error.message` | best-effort; needed only for BLE DK acceptance |
| 4c | `POST {messageCoreUrl}/open-api/v1/mcs/notice/receiver/equipment/relation/sycn` | **user-center client** (DEFAULT_HEADERS + UC HMAC + ucToken) with overrides `app-authorization: 1009`, `client-id: 1d1921ad4d314ab7b0042a2fe0f479c3`, `msgClientId: 1009`, `msgAppId: 10008`, `Brand: ZEEKR` | `{"appId":"10008","deviceToken":"OZ"+deviceIdentifier.replace("-","").take(140),"platformType":1,"receive":"<accountUuid or ''>","region":"<snsRegion>"}` | logs `code`, `data.endpoint` | best-effort. Purpose: claim the account's single active-device slot (dummy device token). The real FCM registration (§7) re-registers later with the overseas signer. |
| 5 | `POST {TSP}ms-user-auth/v1.0/auth/login` | TSP (X-SIGNATURE) | `{"identifier":"<tspCode>","identityType":10,"loginDeviceId":"google-Pixel 7-36-16","loginDeviceJgId":"","loginDeviceType":1,"loginPhoneBrand":"google","loginPhoneModel":"Pixel 7","loginSystem":"Android"}` (sent key-sorted) | `data.accessToken` → **TSP bearer** | on failure falls back to a pre-captured `accessToken` in config, else fatal "no bearer token". `loginDeviceId` MUST be `brand-model-sdkInt-release` format or the backend doesn't treat it as a real device (won't claim/evict sessions). |
| 5b | (local) decode bearer JWT payload (strip `"Bearer "`, base64url) | — | — | claim `userId` → numeric **userId** (preferred over user/info's) | — |
| persist | `accessToken = bearer`, `userId = jwtUserId ?: infoUserId ?: old`, `accountUuid` | | | | before step 6 (needs auth) |
| 6 | `GET {TSP}ms-app-bff/api/v4.0/veh/vehicle-list?needSharedCar=true` | TSP | — | `data` array → `VehicleGarage.parseAll` → garage reconcile (§4.2) and active VIN pick | best-effort (warn if empty → manual VIN) |
| 7 | `POST {TSP}ms-app-online-manager/api/v1.0/app/hb` (heartbeat, §2.4) | TSP | | | best-effort |

Password encryption: `RSA/ECB/PKCS1Padding`, public key = `password_public_key` base64 (DEFAULT decoder) of an X.509 SubjectPublicKeyInfo, plaintext = UTF-8 password, output Base64 NO_WRAP. Never falls back to plaintext.

Response checking (`requireSuccess`): `success == "true"` OR `code == "000000"`, else error `"<hint or 'request failed'> (<code> <msg>) @ <last path segment>"`. Hints only when server `msg` blank: 9007, 9300, 9301.

### 2.3 Token inventory

| Token | Origin | Stored as | Sent as | Lifetime handling |
|---|---|---|---|---|
| ucToken / azureToken | step 2 `tokenValue` (server-issued, HS256 JWT; has `uuid` claim) | `azureToken` (persisted) | `authorization` on UC calls; `Authorization` (verbatim, NO "Bearer") on all `/overseas-app` + message-core calls | none — no refresh; replaced on next login |
| TSP bearer | step 5 `data.accessToken` (JWT; claims incl. `userId`, `openId`, `sub`; may already include `Bearer ` prefix — sent verbatim) | `accessToken` | lowercase `authorization` on every TSP call (and fallback for overseas when azureToken blank) | cleared on 401+079012/079021; no refresh-token flow exists |
| tspCode | step 4 | transient | `identifier` in step 5 | one-shot |
| xchanger authCode | step 4b | transient | body of 4b′ | one-shot |
| xchanger session | 4b′ `clientId`+`accessToken` | `xchangerClientId`, `xchangerToken` | consumed by DK stack (out of scope) | none |
| Inbox HS256 (client-minted) | `InboxAuthToken.mint` | — | — | **abandoned / dead code** (server token replaced it) |

`LoginResponse`/`LoginRequest` + `TspApi.login` (`POST /auth/customer/login`, fields `account,password,accountType="email",regionCode="EU"`; response `access_token|token, userId, refreshToken`) are **unused legacy**; no refresh token is ever used.

### 2.4 Session / single-device behaviour

* Account has ONE online-device slot. Being the online device is required for the car to execute remote commands (otherwise `037005 "execution failed, please try again"`).
* **Heartbeat** `POST {TSP}ms-app-online-manager/api/v1.0/app/hb` body `{"deviceId":"<appInstanceId>","deviceType":1,"hbType":3,"ts":<epoch ms Long>}`.
  * Sent: at login step 7; before every remote command, status fetch, inbox fetch/unread, schedule read/write, journey logging toggle (best-effort, errors ignored); and by a foreground loop (`App.startHeartbeat`): every **30 s** while app foregrounded and `accessToken` non-blank; on auth rejection (`isAuthRejection`: message contains `079020`, `HTTP 401` or `Invalid token`) the interval doubles up to **240 s** and `AuthAlertState.onAuthRejected(code)` is called; a banner shows after **3** consecutive auth failures ("wrong region?"); any success resets. Network errors keep the 30 s cadence. A "Re-check now" signal wakes the wait immediately. Loop stops when app backgrounded (not run from the BLE service).
* `appInstanceId` = random UUID (stock format) used as `x-device-id` + hb `deviceId`; `deviceIdentifier` = `"OZ-" + 24 hex chars` (own stable id; used for DK, push dummy token, sentry live `userId`, xchanger `X-DEVICE-IDENTIFIER` = first 16 bytes of SHA-256(deviceIdentifier or "openzeekr") hex = 32 hex chars). Both regenerated after sign-out (fresh device slot).
* **KickoutInterceptor** (first interceptor on the TSP client; peeks ≤1024 B of every HTTP 401 body):
  * contains `079021` ("account logged in elsewhere", e.g. stock app took the slot) → clear `accessToken`, `SessionSignal.loggedInElsewhere = true`.
  * contains `079012` ("Token expired") → clear `accessToken`, `SessionSignal.sessionExpired = true`.
  * UI shows a snackbar and resets the flag; user lands in the signed-out flow. **No automatic re-login** — login is only triggered manually (Settings "Sign in" / onboarding). Email+password remain stored, so a rewrite could auto-relogin.
* Re-login triggers in practice: 079012, 079021, persistent 079020/401 (banner), region change, sign-out.
* Sign-out (`SecretsConfig.signedOut()`): clears email, password, accessToken, azureToken, xchangerToken, xchangerClientId, userId, accountUuid, isOwner, vin, carNickname, vehicles, deviceIdentifier, appInstanceId, both geofence lists, proximityDeviceMac; switches off autoSentryOnLock & proximityEnabled. Keeps app-global secrets, region/hosts, calibration, UI prefs. `PushRegistrar.disableOnLogout()` is fired from Settings.

---------------------------------------------------------------------------------------------------

## 3. Request signing

All HMACs: key = `secret.toByteArray(UTF-8)`, output standard Base64 (NO_WRAP unless stated).

### 3.1 User-center HMAC (`Signing.usercenterHmac`) — backend A

```
date        = format(nowUTC, "EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)   // abbreviated weekday, e.g. "Mon, 14 Sep 2026 09:24:56 GMT"
segs        = URI(url).path (decoded).trim('/').split('/').filter(nonEmpty)
canonPath   = segs.isEmpty ? "/" : "/" + segs.join("/")                       // collapses '//' and drops trailing '/'
canonQuery  = rawQuery (still percent-encoded) split '&' -> k=v (pairs w/o '=' dropped; later dup key wins)
              keys sorted by key.lowercase(); join "k=v" with '&'; "" if none
stringToSign= METHOD.upper + "\n" + canonPath + "\n" + canonQuery + "\n" + accessKey + "\n" + date + "\n"
X-HMAC-SIGNATURE = B64(HMAC_SHA256(hmac_secret_key, stringToSign))
X-HMAC-DIGEST    = B64(HMAC_SHA256(hmac_secret_key, bodyUtf8String or "" if no body))
X-HMAC-ALGORITHM = "hmac-sha256"
X-HMAC-ACCESS-KEY= hmac_access_key
X-DATE           = date
```
Body digest is over the exact bytes sent (POSTs with no payload send `{}`, so digest of `"{}"`).

### 3.2 TSP X-SIGNATURE (`Signing.tspSignature` + `HeaderInterceptor` + `SignInterceptor`) — backend B

Interceptor order on the TSP OkHttp client: `KickoutInterceptor` → `HeaderInterceptor` → `SignInterceptor` → `OverseasAppAuthInterceptor` → log-level gate → logging. HeaderInterceptor/SignInterceptor **pass through** any request whose `encodedPath` starts with `/overseas-app` (handled by 3.3 instead).

**HeaderInterceptor** adds (only if caller hasn't set the header):
```
ACCEPT-LANGUAGE: en-GB
AppId: ONEX97FB91F061405
Content-Type: application/json; charset=UTF-8        // set even on GET
user-agent: okhttp/4.12.0
X-API-SIGNATURE-VERSION: 2.0
X-APP-ID: ZEEKRCNCH001M0001
X-APP-OS-VERSION: ""                                  // empty value, stock sends it
x-device-id: {appInstanceId}
x-p: Android
X-PLATFORM: APP
X-PROJECT-ID: {projectId}
```
then `authorization: {accessToken}` if non-blank, then `x-vin: VinCrypto.encryptVin(vin, vin_key, vin_iv)` **only if** vin, vin_key and vin_iv are all non-blank (else omitted).

**SignInterceptor**:
1. set `X-API-SIGNATURE-NONCE: UUID.randomUUID()` (36-char hyphenated) and `X-TIMESTAMP: System.currentTimeMillis()` (ms string).
2. If body content-type is `application/*json*` and non-empty: re-serialize body as **canonical JSON** = parse, recursively sort object keys (natural `String` order), arrays keep order, compact (`kotlinx JsonElement.toString()`: no whitespace). **The canonical bytes are what is SENT** (gateway MD5s the received body; unsorted body ⇒ `079025`). Force `Content-Type: application/json; charset=UTF-8`.
3. Compute signature over the final request and set `X-SIGNATURE`.

```
ALLOWED = {x-app-id, content-type, x-api-signature-nonce, x-timestamp, x-api-signature-version,
           x-project-id, authorization, accept-language, x-vin, x-device-id, x-platform}
hdr   = for each request header (name lowercased): keep if name in ALLOWED and not ((name=="x-vin"||name=="authorization") && value=="")
        sort by name; concat "name:value\n"                        // value verbatim, not trimmed
query = rawQuery (encoded) split '&' -> map k->v (no '=' => v ""), keys sorted (case-sensitive natural);
        v = v.replace("%2F","/").replace("%3F","?").replace("*","%2A"); join "k=v" with '&'
bodyHash = (content-type contains application/json && body non-empty) ? B64(MD5(canonicalJson(body))) : ""
base  = hdr
      + (query  != "" ? query + "\n"    : "")
      + (bodyHash!= "" ? bodyHash + "\n" : "")
      + METHOD.upper + "\n"
      + URI(url).path (decoded path, trimEnd whitespace)           // e.g. "/ms-vehicle-status/api/v1.0/vehicle/status/latest"
X-SIGNATURE = B64(HMAC_SHA256(prod_secret, base))
```
Note the signed headers are taken from OkHttp application-level headers (before BridgeInterceptor), so Host/Accept-Encoding/Content-Length are never signed. Unused field `signAlgo="sha256"` exists in config; only SHA-256 is implemented.

### 3.3 Overseas-app HMAC (`OverseasSign` + `OverseasAppAuthInterceptor`) — backend C

Applies to requests whose `encodedPath` starts with `/overseas-app` (via the TSP Retrofit client with absolute `@Url`), and is re-implemented standalone by `PushRegistrar` for message-core.

If `overseas_access_key` or `overseas_secret_key` blank → request is sent **unsigned** (fails 401 cleanly; signing with empty key would crash).

```
xDate        = format(nowUTC, "EEEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)   // FULL weekday, e.g. "Monday, 14 Sep 2026 09:24:56 GMT"
path         = HttpUrl.encodedPath                                           // as-is (no slash normalisation)
sortedQuery  = HttpUrl query params with DECODED names/values (null value -> ""), stable-sorted by name.lowercase(), "k=v" joined '&'; "" if none
stringToSign = METHOD + "\n" + path + "\n" + sortedQuery + "\n" + accessKey + "\n" + xDate + "\n"
X-HMAC-SIGNATURE = B64(HMAC_SHA256(overseas_secret_key, stringToSign))
X-HMAC-DIGEST    = B64(HMAC_SHA256(overseas_secret_key, bodyBytes or empty))
```
Headers added (overwrite):
```
X-DATE: {xDate}
X-HMAC-ALGORITHM: hmac-sha256
X-HMAC-ACCESS-KEY: {overseas_access_key}
X-HMAC-SIGNATURE / X-HMAC-DIGEST
App-Code: 1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc
appId: TSP
appCode: eu-app
appSecret: zeekr_tis
Tmp-Tenant-Code: 3300671070785540000          // NB differs from DEFAULT_HEADERS tenant 3300743799505195008
Brand: ZEEKR
Client-Id: 1d1921ad4d314ab7b0042a2fe0f479c3
app-authorization: 1009
msgClientId: 1009
msgAppId: 10008
Device-Type: app
Call-Source: android
Authorization: {azureToken}  (else {accessToken} if azureToken blank; verbatim, no "Bearer")
```
(The missing app-authorization/msgClientId/msgAppId trio was the historic /overseas-app 401.) The body is NOT canonicalized here; digest is over bytes as sent. Note: these requests still pass through `KickoutInterceptor`.

### 3.4 xchanger HF sign (`AccountLogin.hfSign`) — backend D (HMAC-SHA1)

Port of stock `com/baselinelibrary/sign/SignUtil.sign`.
```
inputs: secret = xchanger_sign_secret, url, method="POST", body (compact JSON string), nonce=UUID, version="1.0",
        timestamp=currentTimeMillis string, accept="application/json;responseformat=3"
headersPart = (accept != "" ? accept.trim() + "\n" : "")
            + for (name,value) in TreeMap{"X-api-signature-nonce":nonce, "X-api-signature-version":version} (sorted by name):
                  name.lowercase() + ":" + value.trim() + "\n"
              // => "x-api-signature-nonce:<nonce>\nx-api-signature-version:1.0\n"
paramsPart  = query of url (after '?') split '&' -> sorted map (raw values) ->
              join "k=" + v.replace("+","%20").replace("*","%2A").replace("%7E","~").replace(",","%2C") with '&'
              // for the session URL: "identity_type=zeekr"
md5Part     = AndroidBase64.DEFAULT(MD5(body UTF-8))     // DEFAULT ⇒ ends with a trailing "\n" (load-bearing!)
path        = url without scheme+host, up to '?'          // "/auth/account/session/secure"
stringToSign= headersPart + "\n" + paramsPart + "\n" + md5Part + timestamp + "\n" + method + "\n" + path
X-SIGNATURE = AndroidBase64.DEFAULT(HMAC_SHA1(secret, stringToSign)).trim()
```
Request headers for 4b′ (exact): `urlname: user-api`, `X-APP-ID: <xchangerAppId(region)>`, `Accept: application/json;responseformat=3`, `Connection: close`, `X-AGENT-TYPE: android`, `X-DEVICE-TYPE: mobile`, `X-OPERATOR-CODE: ZEEKR`, `X-DEVICE-IDENTIFIER: <32-hex>`, `X-ENV-TYPE: production`, `Accept-Encoding: identity`, `X-VERSION: zeekrNew`, `X-TIMEZONE: <TimeZone.getDefault().id>`, `Accept-Language: en_US`, `X-api-signature-version: 1.0`, `X-api-signature-nonce: <nonce>`, `X-DEVICE-MANUFACTURE: google`, `X-DEVICE-BRAND: panther`, `X-DEVICE-MODEL: Pixel 7`, `X-DEVICE-RELEASE-DATE: ""`, `X-AGENT-VERSION: 16`, `X-SIGNATURE`, `X-TIMESTAMP`, Content-Type `application/json; charset=UTF-8`. No `PLATFORM` header for ZEEKR. Missing signature → `1440 "验签签名不存在"`; CN host `api.xchanger.cn` → `1440 "验签APP不存在"`.

### 3.5 VIN encryption (`VinCrypto.encryptVin`) — `x-vin` header

```
if vin blank -> return vin
if vin_key startsWith "B64:" and length>4 -> return vin_key.removePrefix("B64:")   // escape hatch: precomputed ciphertext used verbatim
if vin_key or vin_iv blank -> return vin (plain)   [HeaderInterceptor won't send x-vin in that case anyway]
key = vin_key UTF-8 bytes, iv = vin_iv UTF-8 bytes (the 16 ASCII chars themselves, NOT hex/base64-decoded); both must be exactly 16 bytes else return plain vin (logged)
x-vin = Base64.NO_WRAP( AES/CBC/PKCS5Padding encrypt(key, iv, vin UTF-8) )        // AES-128; 17-char VIN -> 32 bytes -> 44 b64 chars
```
Deterministic (fixed IV) → can be computed once per VIN. Validation (`SecretsConfig.validate`): vin_key/vin_iv must be 16 bytes when non-empty, unless key starts with `B64:`.

### 3.6 Inbox HS256 token (dead, documented for completeness)
`header_b64 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"` ({"typ":"JWT","alg":"HS256"}); payload compact `{"loginType":"login","uuid":"<openId>","Client-Id":"1d1921ad4d314ab7b0042a2fe0f479c3","timeMillis":<ms>}`; token = h.p.base64url(HMAC_SHA256(inbox_auth_secret, "h.p")), base64url no padding. Replaced by server-issued azureToken; `inbox_auth_secret` is unused at runtime.

---------------------------------------------------------------------------------------------------

## 4. Endpoint catalog

Conventions: **TSP** = `{baseUrl}/` + path, full X-SIGNATURE stack, VIN implicitly in `x-vin` header. **AZ** = `{azureHost}` absolute URL, overseas HMAC stack. Retrofit Json: `ignoreUnknownKeys=true, encodeDefaults=false, isLenient=true` — properties equal to their Kotlin default are DROPPED from the wire; nulls of fields without defaults are emitted as `null`.

### 4.1 Table

| # | Method | Service / path | Params / body | Response fields used | Purpose / notes |
|---|---|---|---|---|---|
| **User-center (A)** |||||
| U1 | POST | `{UC}auth/checkUserV2` | `{email, checkType:"1"}` | envelope | login step 1 |
| U2 | POST | `{UC}auth/loginByEmailEncrypt` | `{code:"", codeId:"", email, password:<RSA b64>}` | `data.tokenName`, `data.tokenValue` | step 2 |
| U3 | POST | `{UC}user/info` | `{}` | `data.userId|id`, `data.uuid`, country fields | step 3 |
| U4 | GET | `{UC}user/tspCode?tspClientId=<client>` | client = TSP client id or xchanger client id (+ header overrides) | `data.code` | steps 4 / 4b |
| U5 | — | `region/url`, `protocol/service/getProtocol`, `member/inbox/home` (INBOX_URL), `user/updateLanguage` | — | — | constants in ZeekrConst, **never called** (region discovery skipped; region/url returns an empty messageCoreUrl) |
| **xchanger (D)** |||||
| X1 | POST | `{xchangerHost}/auth/account/session/secure?identity_type=zeekr` | `{authCode}` | `code=="1000"`, `data.clientId`, `data.accessToken` | DK backend session |
| **TSP (B) — account / device** |||||
| T1 | POST | `ms-user-auth/v1.0/auth/login` | see 2.2 step 5 | `data.accessToken` | TSP bearer |
| T2 | POST | `ms-app-online-manager/api/v1.0/app/hb` | `{deviceId:appInstanceId, deviceType:1, hbType:3, ts:<ms>}` | envelope | online-device heartbeat |
| T3 | GET | `ms-app-bff/api/v4.0/veh/vehicle-list?needSharedCar=true` | always `true` in practice (false returns empty for shared-only accounts) | `data` (array \| `{list|records|vehicleList}` \| single) items: `vin`, `isOwner` ("true"/"1"), `nickName|vehicleNickname|vehNickname|remark`, `modelName|seriesName|appModelCode|appInnerCode|innerCode|seriesCode`, `colorName|appColorCode|colorCode|vehicleMaterials[].materialName`, `vehiclePhotoBig|vehicleListImgUrl|vehiclePhotoSmall`, `id|vehicleId|relationId`, `appModelCode|appInnerCode|seriesCode` (→OTA seriesCode), `appYearCode|modelCode` (→OTA modelCode) | garage; e.g. appModelCode `CC1E`=7GT, appInnerCode `CX1E…`=7X |
| T4 | POST | `ms-tsp-user-vehicle/api/v1/veh/owner/relation/modify-vehicle` | `{id?:<vehicleId>, vehNickname, vehiclePlateNum?}` (nulls dropped) | envelope | rename car |
| T5 | GET | `ms-vehicle-capability/api/v1.0/vehicle/function/model/info` | — | array of beans `{functionCode, paramCode, paramValueCode, paramValueUse}` | capability gating (§6.4) |
| T6 | GET | `ms-mno-service/api/v1.0/app/vehicle/data/usage/info` | — | `{total, usage, remain}` (strings, GB), `simStatus:Int`, `queryTimeMillis:Long` | eSIM data plan |
| **TSP — status** |||||
| T7 | GET | `ms-vehicle-status/api/v1.0/vehicle/status/latest?latest=false&target=new` | both query params required (stock) | big tree, §5 | vehicle status |
| T8 | GET | `ms-app-bff/api/v1.0/remoteControl/getVehicleState` | — | flat-ish object: `vstdModeState` ("1"=sentry/guard armed), `visitorModeState` ("1"), `journalLogState` ("1"/"0"), `storageBoxStatus: [{boxId, status,…}]` (glovebox = boxId "3" status, "1" locked), others | live mode toggles; values mix strings/null/arrays |
| **TSP — remote control** |||||
| T9 | POST | `ms-remote-control/v1.0/remoteControl/control` ("System A") | `{command, serviceId, setting:{serviceParameters:[{key,value}…], operationScheduling?:{duration}}}` | `data:{serviceId, operationId, status}`; error if `data` null | all non-RCS, non-System-B commands (§6) |
| T10 | POST | `ms-charge-manage/api/v1.0/charge/control` | same shape as T9, serviceId `RCS` | same | charge start/stop/limit/current |
| T11 | PUT | `remote-control/vehicle/telematics/{vin}` ("System B", ecarx device-api) | flat `{serviceId, command, creator:"tc", userId:<numeric userId>, timestamp:"<ms>", serviceParameters:[…], operationScheduling:{} or {duration:n}}` | `{code:Int, message, success, sessionId, data:{serviceId,operationId,status}}`; ok = success \|\| code 1000 \|\| code 200 | powered tailgate `RDU_2`/`RDL_2` only |
| T12 | POST | `ms-vehicle-trail/v1.0/journalLog/onOff` | `{command:"start"|"stop", serviceId:"JOU", setting:{serviceParameters:[{key:"jou", value:"1"(on)|"2"(off)}]}}` | envelope; ok = success \|\| code null \|\| "000000" | trip recording switch (vehicle-relayed; confirm via T8 `journalLogState`). CN-only `/remote-control/ihu/jou/*` 404s (00A01). |
| T13 | POST | `ms-lbs-service/api/v2.0/sendToCar` | `{address, city, content:"", csys:"WGS-84", longitude:Double, latitude:Double, name (default "Destination"), source:"zeekr"}` | `data.msgId`; fail if !success && data null | push POI to car nav (raw WGS-84) |
| **TSP — schedules** |||||
| T14 | GET | `ms-charge-manage/api/v1.0/charge/getChargingPlan` | none | `{timerId, target, startTime, endTime, command, scheduledTime, setting, dataSource ("DHU"/"APP"), bcTempActive, bcCycleActive, updateTime}` | V1 single daily charge window |
| T15 | POST | `ms-charge-manage/api/v1.0/charge/setChargingPlan` | `{bcCycleActive:false, bcTempActive:false, command:"start"|"stop", startTime?:"HH:mm", endTime?:"HH:mm" (omitted on stop), scheduledTime:"<epoch ms next trigger>", target:"1"(keep charging past end)|"2", timerId:"<readback, default '2'>"}` — NO serviceId | sessionId; confirm by polling T14 (8×2 s) until `command` matches and `dataSource=="APP"` | V2 booking-charge (`getBookingCharge`) 400s with `000002 "groupNumber必须大于等于1"` on EU car → unused |
| T16 | POST | `/ms-charge-manage/api/v2.0/charge/getTravelPlan` | **empty body**, POST | `data: [BookingTravelSetting]` | departure plans |
| T17 | POST | `/ms-charge-manage/api/v2.0/charge/setTravelPlan` | `{command:"start"(create)|"edit"|"stop"(delete), serviceId:"ZAO", setting:BookingTravelSetting}` | `data.sessionId` or `sessionId`; ok = success \|\| sessionId; `088028` = car offline & command queue full | departure create/update/delete (queued, no readback poll) |
| **TSP — journeys** |||||
| T18 | POST | `ms-vehicle-trail/v1.0/journalLog/trip/listForPage` | `{current, pageSize (10), startTime:<ms>, endTime:<ms>, lastId:-1}` (default window 90 d) | `data:{current, pageSize, total, pages, lastId, data:[trip]}`; trip: `reportTime, tripId, startTime, endTime, startOdometer, endOdometer, traveledDistance (km), avgSpeed (km/h), calAvgSpeed, electricConsumption, electricRegeneration, fuelConsumption, trackPoints[{latitude,longitude,…}], wayPointList` | trip history; owner-only; retry up to 20× with 600 ms on HTTP 500/502/503/504 |
| T19 | GET | `ms-vehicle-trail/v1.0/journalLog/trackpoint/list?tripReportTime=<ms>&tripId=<int>` | | `data:[{systemTime, latitude, longitude, altitude, speed, direction, odometer}]` | per-trip GPS track |
| **TSP — car sharing** |||||
| T20 | GET | `ms-tsp-user-vehicle/api/v2/veh/authorize/acceptlist?userId=<id>&current=1&pageSize=50` | try `userId` (JWT) first, then `accountUuid` if empty | list (array \| `{data|list|records}`) of `{id|shareId, vin, modelName|vehicleName|modelCode, ownerName, ownerEmail|ownerPhone, functionNames, function:[…], startTime, endTime, expireTime, acceptTime}` (times in epoch **seconds** or ms) | invites to me; pending = acceptTime null && not expired/ended |
| T21 | POST | `ms-tsp-user-vehicle/api/v2/veh/authorize/accept` | `{shareId, toUserId:<userId>, isAccept:Boolean}` | ok = success \|\| code null \|\| "000000" | accept/decline; then refresh T3 and activate VIN |
| T22 | GET | `ms-tsp-user-vehicle/api/v2/veh/owner/authorize/list?userId=<id>&current=1&pageSize=50` | same id fallback | `{id|shareId, toUserName, toUserEmail|toUserPhone, status, functionNames|function[], startTime, endTime, expireTime, shareType}` | my outgoing shares (don't filter on expireTime: permanent DK shares report stale past expireTime) |
| T23 | POST | `ms-tsp-user-vehicle/api/v2/veh/owner/authorize/cancel` | `{shareId}` | ok as above | revoke share |
| T24 | POST | `ms-tsp-user-vehicle/api/v2/veh/owner/authorize/create` | `{toUserEmail, toUserName:<local part>, shareType:2 (permanent), serviceCodeList:["digital-key","remote-control","view-vehicle-location","view-vehicle-album"], supportSubSharing:0, vin, systemType:"GEEA2.0"}` | ok as above | invite by email |
| **TSP — sentry (sentinel-monitoring-service)** — NOT routed on EU gateway (404/`00A01`) |||||
| T25 | GET | `/sentinel-monitoring-service/api/v1/alarm/event/query?alarmVin&alarmStartTime&alarmEndTime&pageNo=1&pageSize=999` | ms timestamps | `data.items[{id, alarmVin, alarmTime, alarmLevel, alarmStatus, alarmImageUrl, alarmVideoUrl, alarmVideoLength, alarmVideoDuration}]` | event list |
| T26 | POST | `/sentinel-monitoring-service/api/v1/alarm/event/launchUploadVideo` | `{ids:[Long]}` | — | ask car to upload clip; then poll T25 every 3 s ×40 for `alarmVideoUrl` |
| T27 | POST | `/sentinel-monitoring-service/api/v1/alarm/live/app/getToken` | `{roomId, userId:<deviceIdentifier>}` | `{accessToken, expireAt, issuedAt, joinRoomId, joinUserId}` | live view RTC token (RTC SDK unidentified) |
| T28 | GET | `/sentinel-monitoring-service/api/v1/alarm/live/app/launchLive?alarmVin=<vin>` | | `{appId, roomId, liveDuration}` | |
| T29 | GET | `/sentinel-monitoring-service/api/v1/pic/list` | | `items` | parking snapshots — declared, **unused** |
| **TSP — digital key (DkProvisioning, out of this scope; paths only)** |||||
| T30 | POST/GET | `ms-tsp-dkbs-geely/api/v1.0/app/certificatecenter/create-app-certificate`; `…/app/digital-key-center/{key-list, share-key, create-owner-blu-key, create-share-key, key-info(GET), repush-key-to-vechile, remove-one-key, sync-key-list, key-status(GET), loop-key-status(GET), phonecoef(GET), pairing-code(GET)}` | — | — | see DK spec |
| **Azure overseas-app (C)** |||||
| A1 | GET | `{azureHost}/overseas-app/member/inbox/home` | none | grouped: groups `VEHICLE/OTA/AFTER_SALES/ZEEKR` each with `customTypeId`, `noticeDTO` (latest msg), `sum` (total, NOT unread), `statistics.*: {id (=customTypeId), unReadNum, typeName}` (e.g. ALERT, LOG, OTA_SERVICE, AFTER_SALES_ORDER) | unread = Σ every `unReadNum`; category list |
| A2 | GET | `{azureHost}/overseas-app/member/inbox?pageNumber=&pageSize=&customTypeId=<id>&vin=` | `customTypeId` REQUIRED (400 without); `vin` sent EMPTY (stock) | list in `objects|records|list|rows|items|content` (or nested `data`); msg fields `id|messageId|noticeId|inboxId`, `title|name|subject|noticeTitle`, `detail|content|body|text|summary|noticeContent`, `customTypeId|category|type|bizType|groupType`, `redirectUrl|url|linkUrl|jumpUrl`, `attachment|imageUrl|image|iconUrl|picUrl`, time `createTime|sendTime|createdTime|time|gmtCreate|pushTime` (ms or ISO), read `read|isRead|readFlag|hasRead` | paged history per category |
| A3 | PUT | `{azureHost}/overseas-app/member/inbox/{id}` | no body | — | mark read (only verified read op) |
| A4 | POST | `{azureHost}/overseas-app/member/inbox/read-all` | `{customTypeId?, vin?}` | — | reversed, never seen in stock; best-effort catch-all |
| A5 | GET | `{azureHost}/overseas-app/member/inbox/unread` | | | declared; **500s**, unused |
| A6 | GET | `{azureHost}/overseas-app/ucd/service/vehicle/config/{VIN}` | | `data.exDecoration.featureName` (real paint, e.g. "Mystic Lilac"), `data.seriesName` ("Zeekr 7GT EU"); RHD/LHD sniffed by regex over all keys/values (`\bRHD\b|right[-_ ]?hand[-_ ]?driv` / LHD) | identity; cached per VIN (misses cached too) |
| A7 | POST | `{azureHost}/overseas-app/ota/os/versionV2` | `{modelCode:<appYearCode>, seriesCode:<appModelCode>, vehicleModelNo:<appModelCode>, vehicleVin}` | `currentVehicleVersion.{displayVersion, bssPackageReleaseNotes[].description}`, `targetVehicleVersion.{…}`, `hasNewAssignment`, `isConfirm`, `newStatus` (top-level or `assignmentInfo.newStatus`), `progress`/`reason` (numeric ⇒ %), `assignmentInfo.{availableAssignmentId(Long), installationOrderId, totalInstallationTime(s), scheduledTime}`; `!success` + `3000013`/"relationship" ⇒ shared account, owner-only | OTA check / progress poll |
| A8 | POST | `{azureHost}/overseas-app/ota/os/download` | `{vehicleModelNo, vehicleVin}` | — | manual download kick (errors ignored), then re-read A7 |
| A9 | POST | `{azureHost}/overseas-app/ota/os/installation` | `{availableAssignmentId:Long, installationOperation:"INSTALL"|"SCHEDULE_INSTALL", installationOrderId, scheduledTime: null | "yyyy-MM-dd HH:mm:ss" (local), vehicleCurrentVersion, vehicleModelNo, vehicleTargetVersion, vehicleVin}` | — | install now / schedule (no separate confirm; disclaimer client-side) |
| A10 | POST | `{azureHost}/overseas-app/ota/os/cancel` | `{availableAssignmentId, installationOrderId, vehicleCurrentVersion, vehicleModelNo, vehicleTargetVersion, vehicleVin}` | — | abort assignment (dev tool for stuck NOK sync) |
| **Message-core (C, standalone client)** |||||
| M1 | POST | `{messageCoreUrl}/open-api/v1/mcs/notice/receiver/equipment/relation/sycn` (sic) | `{"appId":"10008","deviceToken":"<fcm>","platformType":1,"receive":"<openId>","region":"<snsRegion>"}` (exact order, manual JSON) | `{code:200, msg:"success", data:{endpoint:"arn:aws:sns:<region>:…:endpoint/GCM/appFcmProd/…"}}` | FCM registration (§7); also used by login 4c with UC signing + dummy token |
| M2 | POST | `{messageCoreUrl}/open-api/v1/mcs/notice/receiver/equipment/relation/disable` | `{"appId":"10008","deviceToken":"<fcm>","receive":"<openId>"}` | — | unregister on logout |
| **GitHub** |||||
| G1 | GET | `https://api.github.com/repos/borconi/openzeekr/releases/latest` | headers `Accept: application/vnd.github+json`, `User-Agent: openzeekr-app` | `tag_name` (strip v/V → version), `html_url` (fallback `https://github.com/borconi/openzeekr/releases/latest`), `body` | update check once on launch + manual; 60 req/h unauth limit. `isNewer`: strip v, drop `-`/`+` tail, numeric dot compare. (Fork owner: change repo path.) |

### 4.2 Garage reconcile (`ConfigStore.reconcileGarage`)
Given fresh `[VehicleRef(vin, name=server nickname or "", isOwner)]`: no-op if empty; per car, server nickname wins; if blank keep prior local name unless it looks like a platform code (`^[A-Z]{2}\d[A-Z](-[A-Z0-9]+)?$`, e.g. `CC1E`, `CX1E-EU`); active VIN kept if still present else first car; `isOwner`/`carNickname` follow the active car. Called at login step 6, every `vehicleInfo()` refresh, and after share accept. Never use the model code as a name.

### 4.3 Departure plan object (`BookingTravelSetting`) — exact wire shape
```
{ "btId": Int (>=1 on create; server assigns real id),
  "name": String,
  "sts": 1|0, "displaySts": 1|0,
  "bookingType": 1 (recurring, uses cycleTimes) | 0 (one-off, needs real temporaryTime),
  "temporaryTime": "yyyy:MM:dd:HH:mm:ss"   // a REAL next-departure anchor; placeholder/near date ⇒ car error FCM 6074 "too close to departure time"; fallback placeholder "2099:12:12:08:00:00"
  "cycleTimes": [ {day:1..7 (1=Mon … 7=Sun), sts:1|0, time:"HH:mm:00"} ×7 ],
  "preHeatSts": 1|0,                                   // battery preheat
  "csSetting":   {duration:10, sts:1|0, temp:"22.0"},  // cabin climate
  "ventiSettings":[{duration:10, level:1, location:1|2, sts:0}],            // REQUIRED non-empty
  "heatSettings": [{duration:10, level:1, location:1|2|3|5, sts:0}],        // REQUIRED non-empty
  "whlSetting":  {duration:10, level:2, sts:0},                             // REQUIRED
  "fragSetting"?: {channel, duration, level, sts} }
```
Missing temporaryTime/ventiSettings/heatSettings/whlSetting ⇒ 400 `000002 "… cannot be empty"`. On edit/delete re-send a sanitized readback (fill missing blocks, btId ≥1, recompute anchor).

---------------------------------------------------------------------------------------------------

## 5. Vehicle status model (T7 `data`)

Parsing is **tolerant** (raw JsonObject; any primitive read as string then converted; bool accepts `true/false/1/0`). Top-level: `basicVehicleStatus`, `additionalVehicleStatus`, `testCall` (bool), `updateTime` (epoch ms, snapshot freshness). Only key names (never values) are logged, and only when the key tree changes.

| Raw JSON path | Type | Unit / meaning / quirk |
|---|---|---|
| `basicVehicleStatus.carMode`, `.usageMode`, `.keyStatus` | str enum | raw |
| `basicVehicleStatus.engineStatus` | str | `"engine-off"` = parked; anything else non-blank ⇒ driving (poll fast) |
| `basicVehicleStatus.distanceToEmpty` | str | range, km |
| `basicVehicleStatus.speed` / `.speedUnit` | int / str | km/h; >0 ⇒ moving |
| `basicVehicleStatus.position.{latitude, longitude, altitude}` | double | WGS-84 degrees (used as car location & for geofence tests) |
| `basicVehicleStatus.position.direction` / `.posCanBeTrusted` | int / bool | |
| `additionalVehicleStatus.drivingSafetyStatus.centralLockingStatus` | str | `"1"` locked, `"0"` unlocked (UI treats null as locked) |
| `…drivingSafetyStatus.doorOpenStatus{Driver,DriverRear,Passenger,PassengerRear}` | str | open = non-blank and != `"0"` |
| `…drivingSafetyStatus.doorLockStatus{Driver,DriverRear,Passenger,PassengerRear}` | str | |
| `…drivingSafetyStatus.engineHoodOpenStatus`, `.trunkOpenStatus` (`"0"` closed), `.trunkLockStatus`, `.electricParkBrakeStatus` | str | |
| `…climateStatus.interiorTemp`, `.exteriorTemp` | str | °C |
| `…climateStatus.preClimateActive` | bool | **authoritative A/C on** |
| `…climateStatus.defrost` | str | `"1"` on |
| `…climateStatus.{drvHeatSts, passHeatingSts, rlHeatingSts, rrHeatingSts}` | str | seat heat level 0–3 (driver, passenger, rear-L, rear-R) |
| `…climateStatus.{drvVentDetail, passVentDetail, rlVentDetail, rrVentDetail}` | str | seat vent level 0–3 |
| `…climateStatus.crSetTemp` | str | A/C setpoint °C if reported (usually not — app remembers last set temp) |
| `…climateStatus.winStatus{Driver,DriverRear,Passenger,PassengerRear}` | str | coarse enum; `"0"`/`"2"` = closed |
| `…climateStatus.winPos{Driver,Passenger,DriverRear,PassengerRear}` | str | **% open** 0 closed / 100 full / 1–99 vent — preferred over winStatus |
| `…climateStatus.sunroofPos` / `.sunroofOpenStatus` | str | pos % preferred; enum: closed is `"1"` (and `"0"`) |
| `…electricVehicleStatus.stateOfCharge` / `.chargeLevel` | str | SOC %. **Use `stateOfCharge` if non-blank else `chargeLevel`** (varies per car) |
| `…electricVehicleStatus.isCharging`, `.isPluggedIn` | bool | **UNRELIABLE / dead** — don't use |
| `…electricVehicleStatus.chargerState` | str int | authoritative: charging ∈ {2,15,24,28,30}; 5 preheat, 6 scheduled, 4/26 complete |
| `…electricVehicleStatus.statusOfChargerConnection` | str int | AC cable: 1/2/3 connected, 0 disconnected, 8 init, 9 fail, 10 partial |
| `…electricVehicleStatus.dcDcConnectStatus` | str int | 1/2/3 = connected |
| `…electricVehicleStatus.chargeLidAcStatus`, `.chargeLidDcAcStatus` | str | `"1"` = flap open |
| `…electricVehicleStatus.chargeIAct`, `.chargeUAct` | str | live AC A / V |
| `…electricVehicleStatus.dcChargePileIAct`, `.dcChargePileUAct` | str | live DC pile A / V (abs value used); `dcChargeIAct` can hold sentinel `-1638.0` — ignore |
| `…electricVehicleStatus.acSettingCurrent` | str | AC current **setpoint** (A) |
| `…electricVehicleStatus.distanceToEmptyOnBatteryOnly` | str | EV range km |
| `…electricVehicleStatus.hvBatteryPreHeatingActive` | bool | battery conditioning |
| `…electricVehicleStatus.averPowerConsumption` / `.averTraPowerConsumption` | str | avg consumption (assumed kWh/100km); use first >0 |
| `…electricVehicleStatus.timeToFullyCharged` | int | minutes to limit; show only while charging and >0 |
| `…maintenanceStatus.odometer` | int | km |
| `…maintenanceStatus.tyreStatus{Driver,DriverRear,Passenger,PassengerRear}` | str | tyre **pressure kPa** |
| `…maintenanceStatus.distanceToService` / `.daysToService` | int | km / days |
| `…maintenanceStatus.mainBatteryStatus.voltage` | double | 12 V battery V |
| `…runningStatus.fuelLevel` / `.fuelLevelPct` | str / int | (PHEV) |

Derived values:
```
dcPower   = (|dcPileI|>0 && |dcPileU|>0) ? |dcPileI|*|dcPileU| : null
chargePowerW = dcPower ?: (I>0 && U>0 ? (U >= 300 ? sqrt(3)*U*I : U*I) : null)   // AC: U>=300 V ⇒ 3-phase line-to-line (heuristic, EU 230/400 V)
chargePhases = DC ? null : (U>=300 ? 3 : 1)
chargingActive = chargerState ∈ {2,15,24,28,30} || chargePowerW > 100 W
pluggedIn   = chargingActive || statusOfChargerConnection ∈ {1,2,3} || dcDcConnectStatus ∈ {1,2,3}
portOpen    = chargeLidAcStatus=="1" || chargeLidDcAcStatus=="1"
acOn = preClimateActive==true; defrostOn = defrost=="1"; seatHeatOn = any heat level > 0
windowsOpen = winPos* reported ? any winPos>0 : any winStatus not in {"", "0", "2"}
windowsVenting = winPos reported && all open windows in 1..99
sunroofOpen = sunroofPos? >0 : sunroofOpenStatus not in {"", "0", "1"}
```
Units for display (`config/Units.kt`): pressure kPa→bar (/100) / psi (×0.1450377) / kPa; °C→°F; km→mi (×0.6213712); speed follows distance unit.

Polling (`VehicleStatusHolder`): no server push. Foreground loop: heartbeat then T7; next delay **5 s** when driving (engine not off or speed>0), else **20 s**. After a successful command: burst refreshes at +1.5 s, +4 s, +8 s (gaps 1500/2500/4000 ms; a new command cancels the in-flight burst). Logs lock/trunk transitions.

---------------------------------------------------------------------------------------------------

## 6. Remote command semantics

### 6.1 Dispatch rules (`RemoteControlRepository.send`)
1. Require active VIN.
2. Heartbeat T2 (best-effort) — car only obeys the online device.
3. If command `requiresLocked` (only `SENTINEL_ON`) and a fresh T7 says `centralLockingStatus=="0"` → refuse ("car must be locked"); unknown state fails open. (Car returns a hollow 200 otherwise.)
4. Route: `serviceId=="RCS"` → T10 (`ms-charge-manage/…/charge/control`); `serviceId ∈ {RDU_2, RDL_2}` → T11 System B PUT (flat body, `userId` = numeric userId); everything else → T9 System A.
5. Success = response `data` non-null (System A/RCS) or ecarx `ok` (System B). **The cloud result is only "accepted/queued"** — the car applies it asynchronously; confirm via status burst (§5). There is no operationId polling endpoint in use.
6. Parameter merge: base params + caller extraParams + (`engStrtType` param if set), **dedup by key, last wins, first-occurrence position kept** (so an override lands in the base slot — matters for RCS positional parsing). `operationScheduling:{duration:n}` only when `durationSec` set (omitted otherwise for System A; `{}` for System B).

BLE-first wrapper (`VehicleControl`): if DK session is `SESSION_READY` and the command has a BLE byte and no extraParams, try BLE (1.5 s ack); fall back to cloud on anything but CONFIRMED. Mapping: UNLOCK 0x01, LOCK 0x02, FLASH_HORN 0x03, FRONT_TRUNK 0x04, TRUNK_UNLOCK 0x06, TRUNK_LOCK 0x07, WINDOW_CLOSE 0x0C, WINDOW_OPEN 0x0D, CHARGE_LID_OPEN 0x13. (WINDOW_VENT not mapped: BLE 0x12 is cabin ventilation.)

### 6.2 Command catalog (exact `serviceId` / `command` / `serviceParameters`)

Body for System A: `{"command":C,"serviceId":S,"setting":{"serviceParameters":[{"key":k,"value":v},…]}}` (+`"operationScheduling":{"duration":n}` where noted). All values are strings.

| Command | serviceId | command | serviceParameters (default) | sched | route | notes |
|---|---|---|---|---|---|---|
| UNLOCK | RDU | stop | door=all | | A | locking=RDL/start, unlocking=RDU/stop (lowercase params) |
| LOCK | RDL | start | door=all | | A | |
| TRUNK_OPEN (powered) | RDU_2 | start | target=trunk | | **B** | latch RDU/stop only releases |
| TRUNK_UNLOCK (latch pop) | RDU | stop | target=trunk | | A | |
| TRUNK_LOCK / power close | RDL_2 | start | target=trunk | | **B** | stock toggles RDU_2 open / RDL_2 close by trunkOpenStatus |
| FRONT_TRUNK (frunk) | RDU | start | target=hood | | A | |
| CHARGE_LID_OPEN | RDO | start | target=front-charge-lid | | A | (moved off System B 2026-09-15) |
| CHARGE_LID_CLOSE | RDC | stop | target=front-charge-lid | | A | |
| AC_ON | ZAF | start | AC=true, AC.temp=22.0, AC.duration=15 | | A | **ZAF always command "start"; on/off is the value.** Temp must be dot-decimal one decimal (`Locale.US "%.1f"`) — comma rejected. UI debounces 600 ms. |
| AC_OFF | ZAF | start | AC=false | | A | |
| CABIN_ON (A/C vent) | RCC | start | rcc.conditioner=50, rcc.ventilation=0 | duration 6 | A | |
| CABIN_OFF | RCC | stop | rcc.conditioner=50, rcc.ventilation=0 | | A | |
| DEFROST_ON | ZAF | start | DF=true, DF.duration=15, DF.level=2 | | A | |
| DEFROST_OFF | ZAF | start | DF=false | | A | |
| SEAT_HEAT_ON (driver) | ZAF | start | SH.11=true, SH.11.level=3, SH.11.duration=15 | | A | positions: 11 driver, 19 passenger, 21 rear-left, 29 rear-right |
| SEAT_HEAT_OFF | ZAF | start | SH.11=false | | A | |
| Per-seat heat (CLIMATE_ZAF + extra) | ZAF | start | level n>0: `SH.<pos>=true, SH.<pos>.level=n, SH.<pos>.duration=15, SV.<pos>=false`; n=0: `SH.<pos>=false` | | A | heat & vent mutually exclusive per seat; UI debounced |
| Per-seat vent/cool | ZAF | start | n>0: `SV.<pos>=true, SV.<pos>.level=n, SV.<pos>.duration=15, SH.<pos>=false`; n=0: `SV.<pos>=false` | | A | stock app doesn't expose cooling |
| A/C with temp (CLIMATE_ZAF) | ZAF | start | AC=true, AC.temp=<t>, AC.duration=15 | | A | |
| STEER_WHEEL_ON | ZAF | start | SW=true, SW.duration=8, SW.level=3 | | A | no reliable readback |
| STEER_WHEEL_OFF | ZAF | start | SW=false | | A | |
| FRAGRANCE_ON | RFD | start | (none) | | A | |
| FRAGRANCE_OFF | RFD | stop | channel_id=0, level=0 | | A | |
| FRIDGE_ON | ZAE | start | operation=1, zae.model=1 (const-temp; 0 otherwise), zae.temp=5.0 (float string, ~-6.0..50.0) | | A | |
| FRIDGE_OFF | ZAE | stop | operation=0 | | A | |
| ENGINE_START | RES | start | engStrtType=1 | duration 60 | A | |
| ENGINE_STOP | RES | stop | engStrtType=1 | | A | |
| WINDOW_OPEN | RWS | start | target=window | | A | serviceId RWS (NOT RWS_2) |
| WINDOW_CLOSE | RWS | stop | target=window | | A | |
| WINDOW_VENT | RWS | start | target=ventilate | | A | |
| SUNROOF_OPEN/CLOSE | RWS | start/stop | target=sunroof | | A | |
| SUNSHADE_OPEN/CLOSE | RWS | start/stop | target=sunshade | | A | |
| CHARGING_ON | RCS | start | rcs.restart=1 | | T10 | |
| CHARGING_OFF | RCS | stop | rcs.terminate=1 | | T10 | |
| SET_CHARGE_SOC | RCS | start | **soc=<pct×10>** (tenths: 80% → "800"; stock 94.9% → "949"), rcs.setting=1, altCurrent=1 | | T10 | **order matters: soc FIRST** else `037000 "parameter is incorrect"`. UI slider min 50%, 5% steps. Limit is not readable — cache last set (`chargeLimitPct`). |
| SET_CHARGE_CURRENT | RCS | start | rcs.ac.current=<amps>, rcs.setting=1 (DC: rcs.dc.current) | | T10 | **Not remotely settable on EU 7GT** (capability `acRange="0"`; stock times out too). Dev-only. |
| BATTERY_PREHEAT_ON/OFF | ZAN | start/stop | (none) | | A | |
| FLASH | RHL | start | rhl=light-flash | | A | |
| HONK | RHL | start | rhl=horn | | A | |
| FLASH_HORN | RHL | start | rhl=horn-light-flash | | A | |
| SENTINEL_ON (sentry) | RSM | start | **rsm=6** (lowercase key) | | A | requiresLocked. Uppercase "RSM" key ⇒ hollow 200; System B ⇒ 404. Valet would be rsm=123456. State: T8 `vstdModeState`. |
| SENTINEL_OFF | RSM | stop | rsm=6 | | A | |
| LOCKER_ON / OFF (private locker) | RDL start / RDU stop | | target=private-lock, password=1234 | | A | placeholder password |
| GLOVEBOX_LOCK / UNLOCK | ZAD | start / stop | code=<PIN> (placeholder 0000), zad.model=1, boxId=3 | | A | state: T8 storageBoxStatus boxId 3 |
| VISITOR_ON / OFF | ZAG | start / stop | code=<PIN>, zag.model=1 | | A | state: T8 `visitorModeState` |
| Journey logging | JOU | start / stop | jou=1 / jou=2 | | T12 | |
| Departure plan | ZAO | start / edit / stop | (setting = BookingTravelSetting) | | T17 | |

### 6.3 Result / error codes seen in code

| Code | Where | Meaning / handling |
|---|---|---|
| `000000` | envelope | success |
| `079012` | TSP HTTP 401 | token expired → clear token, re-login |
| `079020` | TSP | "Invalid token" (often wrong region) → hb backoff + banner |
| `079021` | TSP HTTP 401 | logged in elsewhere → clear token |
| `079025` | TSP | signature verify failed (body not canonical/sorted) |
| `037005` | remote control | "execution failed, please try again" — not online device / wrong body shape (e.g. params at top level) |
| `037000` | RCS | "parameter is incorrect" (soc not first) |
| `00A01` | TSP 404 | route not deployed on this gateway (sentinel, CN ihu/jou) |
| `000002` | ms-charge-manage | validation ("groupNumber必须大于等于1", "… cannot be empty") |
| `088028` | setTravelPlan | car offline AND cached-command queue full |
| `6074` (FCM) | departure | "too close to departure time" (bad temporaryTime) |
| `3000013` | OTA versionV2 | "human-vehicle relationship cannot be operated" — shared (non-owner) account |
| `9007` | checkUserV2 | account not in this region's tenant |
| `9300`, `9301` | loginByEmailEncrypt | password rejected |
| `1000` | xchanger, ecarx | success (ecarx also `200`) |
| `1440` | xchanger | "验签签名不存在" (no signature) / "验签APP不存在" (wrong/CN host) |
| `200` | message-core | push registration success |
| HTTP 500/502/503/504 | ms-vehicle-trail | flaky upstream → retry (20×, 600 ms) then "service busy" |

Async semantics: cloud 200 + sessionId = queued; car must be awake/online. Charge plan is confirmed by readback; departures cannot be (queued creates don't appear until car drains the queue — repeated retries pile up "BookTravel"/sts=0 entries).

### 6.4 Capability gating (T5)
`codes` = union of non-blank `functionCode`, `paramCode`, `paramValueCode` across beans. `has(k…)` = case-insensitive **substring** match; **fail-open** when list unknown/empty (`known=false`, all true). Feature → keys:

| Feature | has(...) | Fail mode |
|---|---|---|
| frunk | ZK_remote_hood_control, hood | open |
| tailgate | C_RDU_2, trunk | open |
| chargeCover | charging_cover, charge_cover | open |
| sunroof | C_RWS_4, remote_control_skylight_2 | open |
| windows | remote_control_window | open |
| sunshade | functionCode/paramValue == remote_control_curtain_2 (exact, case-insens.) | **closed** |
| engineRes | C_RES | open |
| rpa | RPA | open |
| sentry | sentry | open |
| fridge | ZK_remote_fridge_control, refrigerator (NOT plain "fridge": alarm codes like ZK_fridge_fault_alarm don't imply control) | open |
| fragrance / climate / seatHeat / steeringHeat | fragrance / climate / seat_heating / steering_wheel_heating | open |
| seatCool | seat_ventilation_level, seat_ventilation | open |
| rearSeatCool | bean paramCode == new_seat_ventilation_position AND paramValueCode ∈ {second_row_left, second_row_right} | **closed** (front = main_driver_seat / copilot_seat) |
| charging | V_RCS, RCS | open |
| glovebox | storageBox_codeLock, T_ZAP, ZAD | open |
| visitor | visitor, ZAG, ZAS | open |

Extra computed (kept for reference): `sunroofConfirmed` = functionCode C_RWS_4 with paramValueUse.trim()=="Y"; `seatCoolConfirmed` = functionCode seat_ventilation with paramValueUse=="Y". Fetched once per session; `reload()` on car switch; failure → stays UNKNOWN and retried later.

---------------------------------------------------------------------------------------------------

## 7. Push (FCM)

* Firebase project = the **stock app's** project (config in `core/res/values/secrets_firebase.xml`, not reviewed here). Token via `FirebaseMessaging.getInstance().token`.
* Registration (`PushRegistrar`): on app bootstrap (`registerIfLoggedIn`) and on `onNewToken`. Preconditions (`canRegister`): openId non-blank, overseas AK & SK non-blank, auth token non-blank. openId = `accountUuid` ?: azureToken JWT claim `uuid` ?: bearer claim `openId` ?: bearer claim `sub`. Auth = `azureToken` ?: `accessToken`.
* Request = M1 with a standalone OkHttp client (20 s connect / 30 s read), body built by string concatenation in exact order `appId, deviceToken, platformType, receive, region` (digest is over body-as-sent), headers: `msgClientId: 1009`, `msgAppId: 10008`, `app-authorization: 1009`, `App-Code: 1JwLroFkFFIpgFGdTRrm4_nzkkwDkfHj7RxJQb7J8tc`, `Tmp-Tenant-Code: 3300671070785540000`, `appId: TSP`, `appCode: eu-app`, `appSecret: zeekr_tis`, `Client-Id: 1d1921ad4d314ab7b0042a2fe0f479c3`, `Brand: ZEEKR`, `Device-Type: app`, `Call-Source: android`, `Content-Type: application/json; charset=UTF-8`, overseas X-DATE/X-HMAC-* (§3.3), `Authorization`. Response only logged (no retry).
* Unregister on logout: M2 body `{appId, deviceToken, receive}`.
* Registering claims the account's active push endpoint (single-device semantics; login 4c does it with a dummy token).
* Fallback when push unavailable: `ProximityService` polls inbox (A1 + A2 per category) every **5 min** and notifies messages newer than a persisted high-water mark (`timeMs > lastSeen && !read`; first run only seeds).

**Payload handling (`ZeekrFcmService.onMessageReceived`)**
* `data["url"]` = deep link `zeekr-overseas://…?k=v&…`; query is URL-decoded and carries `title`, `content`, `showBanner`, `showToast`, and for OTA a JSON `data` blob.
* OTA live status: if url contains `OTAAssignmentStatusUpdate` → parse `q["data"]` JSON `{vin, status (hyphen form e.g. "INSTALLATION-PENDING"), reason (status code or numeric % during *-PROGRESS), scheduledTime}` → `OtaStatusBus` (no replay, buffer 16). Silent.
* Title = `notification.title` ?: `data.title` ?: `q.title` ?: "Zeekr". Body = `notification.body` ?: `data.content` ?: `data.body` ?: `data.desc` ?: `q.content` ?: "". Id = messageId ?: `data.msgId` ?: url ?: title+time. Category = `data.bizType`; hints from `bizType, category, type, groupType` in data and query.
* Notify rule: notification payload → always; data-only → only if `showBanner=="true"`, or flag absent and has real text. Many silent data pushes (deliverRemoteControlPush: TRS/RSM/RCS progress) have empty text + `showBanner=false` → ignored.
* Background delivery only for data-only messages; notification-type are shown by the SDK on the fallback channel.

**Categories** (`CarNotificationCategory`, Android channel ids): `car_charging`, `car_security`, `car_vehicle`, `car_updates`, `car_service`, `car_news`, `car_alerts` (OTHER). Classification: hints normalized (camelCase/ACRONYM split, lowercase, non-alnum→space); group hints first: `ota`→UPDATES, `after sales`→SERVICE, `zeekr`→NEWS; then per hint: charging/charge/battery→CHARGING, security→SECURITY, updates/software updates→UPDATES, service/maintenance→SERVICE, news/marketing→NEWS, else title-regex on the hint; finally title regex: news (newsletter|promotion|discount|offer|zeekr news), updates (ota|firmware|software update/upgrade), service (service reminder/due/appointment|maintenance|servicing), security (security|sentry|sentinel|intrusion|break in|theft|tamper|tow AND alert|alarm|warning|detected; or "car/vehicle (is being) towed"|"abnormal parking"), charging (`char?g(e|er|ing)` incl. typo "Chaging", batter(y|ies), state of charge), vehicle (remote control|climate|air conditioning|door|window|lock|unlock|trunk|frunk). VEHICLE group alone ⇒ OTHER. Inbox groups: VEHICLE (charging done/abnormal, alarm/abnormal parking, remote-control results, low battery), OTA, AFTER_SALES, ZEEKR (marketing).

---------------------------------------------------------------------------------------------------

## 8. Secrets & configuration

### 8.1 User-supplied app-global secrets (JSON key = `secrets.example.json` / `zeekr_secrets.json`; properties key = `secrets.properties.example`)

| JSON key | properties key | Used for | Source (per code comments) | Region-specific? |
|---|---|---|---|---|
| `hmac_access_key` | HMAC_ACCESS_KEY | UC HMAC `X-HMAC-ACCESS-KEY` (login + step 4c) | key extractor `--region` | yes (EU/EM/SEA; SEA UC keys host-specific) |
| `hmac_secret_key` | HMAC_SECRET_KEY | UC HMAC secret | key extractor | yes |
| `password_public_key` | PASSWORD_PUBLIC_KEY | RSA (X.509 SPKI b64) password encryption | key extractor; kept in BuildConfig (public) | no |
| `prod_secret` | PROD_SECRET | TSP X-SIGNATURE HMAC-SHA256 key (`signSecret`) | Frida `getTSPSecretValue(<region>,"ONLINE")` | yes (EU/EM/SEA) |
| `vin_key` | VIN_KEY | AES-128 key (16 ASCII bytes) for `x-vin`; `B64:<ciphertext>` escape | Frida | no |
| `vin_iv` | VIN_IV | AES IV (16 ASCII bytes) | Frida | no |
| `xchanger_sign_secret` | XCHANGER_SIGN_SECRET | HF HMAC-SHA1 key for xchanger session | Frida (comment claims same value as prod_secret for EU, but it's configured separately) | no |
| `overseas_access_key` | OVERSEAS_ACCESS_KEY | overseas HMAC AK (inbox, vehicle config, OTA, push) | Frida libenv.so getNativeApplicationId | no |
| `overseas_secret_key` | OVERSEAS_SECRET_KEY | overseas HMAC SK | Frida libenv.so getNativeSecret | no |
| `inbox_auth_secret` | INBOX_AUTH_SECRET | HS256 inbox token — **unused** | Frida | no |

Mandatory for login: hmac pair, password_public_key, prod_secret (`validate()`). Overseas AK/SK must be both set or both blank; blank ⇒ inbox/OTA/paint/push silently unavailable (`overseasReady=false`). vin_key/iv blank ⇒ `x-vin` omitted (most TSP vehicle calls then can't identify the car).

### 8.2 Account / session fields (persisted)
`email`, `password` (plaintext in encrypted prefs, needed for re-login), `vin` (active), `vehicles[] {vin,name,isOwner}`, `isOwner`, `userId` (numeric, from JWT), `accountUuid` (openId), `accessToken`, `azureToken`, `xchangerToken`, `xchangerClientId`, `deviceIdentifier`, `appInstanceId`, plus region/host fields (`baseUrl`, `regionCode`, `countryCode`, `projectId`, `azureHost`, `xchangerHost`, `snsRegion`). Unused/legacy device fields: `appId`, `clientId`, `deviceModel`, `deviceBrand`, `deviceManufacture`, `agentType`, `agentVersion` 3.0.7, `envType`, `appVersion`, `sigVersion`, `signAlgo`. UI-adjacent: `chargeLimitPct` (80), units (`pressureUnit` bar|psi|kpa, `tempUnit` c|f, `distanceUnit` km|mi), `autoSentryOnLock`, `sentryExclusionZones[] {name,lat,lng,radiusMeters=150}`, proximity settings (BLE scope).

### 8.3 Storage
* `ConfigStore`: whole `SecretsConfig` serialized as pretty JSON (`encodeDefaults=true`) under key `config_json` in **EncryptedSharedPreferences** file `openzeekr_secure_config` (MasterKey AES256_GCM; keys AES256_SIV, values AES256_GCM). Exposed as `StateFlow`.
* Build-time baking: gitignored `secrets.properties` → C header → JNI lib `libozsecrets.so` (`NativeSecrets`, per-region getters for EU/EM/SEA hmac+prod); password key via BuildConfig. Obfuscation only, not secrecy. First run seeds from baked values; every load back-fills blank app-global secrets from baked values (user values win). `SECRETS_BAKED` hides secret UI.
* Import (`importJson`): merges only non-blank fields for the secret keys + email/password/vin/accessToken; region fields deliberately not imported; strict `check()`. Export: password and all session tokens blanked unless explicitly included.
* Load-time migrations: ensure device ids; `debugLogging` → `logHttp`+`logBle`.

### 8.4 Logging redaction (`HttpLog`)
Headers redacted: Authorization, X-SIGNATURE, X-Api-Signature, x-sign, X-HMAC-SIGNATURE/ACCESS-KEY/DIGEST, Cookie, Set-Cookie, x-device-id variants, X-DEVICE-IDENTIFIER, x-vin, ak, sk, openId, Client-Id, timeMillis, app-authorization, appSecret, X-API-SIGNATURE-NONCE. Body/query keys (prefix match, case-insens.) scrubbed to `***`: access_token, refresh_token, accessToken, refreshToken, id_token, tokenValue, tokenName, token, password, passwd, pwd, signature, sign, appSecret, secret, openId, deviceIdentifier, deviceId, cmacKey, digitalKey, privateKey, priKey, csr, cert, phoneNumber, mobile, vin, sk, ak. HTTP log level BASIC only when `logHttp` on.

---------------------------------------------------------------------------------------------------

## 9. Quirks, retries, limits, TODOs, known-broken

1. **encodeDefaults=false trap**: any field that must be on the wire must have no Kotlin default (e.g. `RemoteControlSetting.serviceParameters` always emitted even if empty; `SendToCarRequest.csys/source/content` explicit). A rewrite with a different serializer should just always emit required fields and omit nulls of optional blocks.
2. **Canonical JSON for TSP**: send the key-sorted compact body; signing the sorted form while sending unsorted → `079025`. Overseas/message-core bodies are NOT reordered (push body order is stock order).
3. Two HMAC date formats: UC uses `EEE` (Mon), overseas uses `EEEE` (Monday). UC canonical query uses raw-encoded values; overseas uses decoded values.
4. Two different tenant codes: DEFAULT_HEADERS `3300743799505195008`, overseas `3300671070785540000`.
5. Login step 4c signs the message-core call with the **UC** scheme while `PushRegistrar` signs the same endpoint with the **overseas** scheme — both apparently accepted (best-effort; not fully verified).
6. Comment drift: `AccountLogin.execRoot` says Accept-Encoding gzip is set manually — it no longer is; the gunzip branch is just a fallback.
7. Retrofit `vehicleList(needSharedCar=false)` default is wrong for shared-only accounts; always pass `true`.
8. `TspApi.inbox` doc says "same bearer + TSP signing" — stale; overseas interceptor handles it.
9. `/inbox/unread` 500s (use Σ `unReadNum` from `/home`); group `sum` is total count, not unread. Inbox `messages()` returns page 1 only (page>1 → empty). `markAllRead` walks categories with unread (pageSize 30, ≤40 pages) PUTting each id, then best-effort `read-all`.
10. Sentinel-monitoring-service (sentry events/clips/live) **not routed on EU** (404/`00A01`); live-view RTC SDK unknown; `pic/list` unused. Sentry arm/disarm itself works via RSM on System A.
11. AC charge current: not remotely settable on EU 7GT (car-side gate). V2 booking-charge plane unusable on EU car → V1 charging plan.
12. OTA: owner-only; download % lives in `reason` (numeric) not `progress`; status enum (normalize `-`→`_`): download-active {ASSIGNMENT_DATA, ASSIGNMENT_FILE_INFO, SIGNATURE_CERTIFICATE_SYSTEM, DOWNLOAD_CONSENT_GRANTED, DOWNLOAD_STARTED, DOWNLOAD_PROGRESS, DOWNLOAD_PAUSE, DOWNLOAD_DISTRIBUTE_PAUSE}; ready {DOWNLOAD_COMPLETED, READY}; scheduled INSTALLATION_CONSENT_SCHEDULED; installing {INSTALLATION_CONSENT_GRANTED, INSTALLATION_PENDING, INSTALLATION_STARTED, INSTALLATION_PROGRESS, INSTALLATION_DEFERRED, POSTINSTALLATION_START(ED)}; installed {INSTALLATION_COMPLETED, INSTALLATION_FINISHED, POSTINSTALLATION_COMPLETED, COMPLETED, INSTALLED}; failed = *_FAILED, *_FAILED_CRITICAL, *_FAILED_DISTRIBUTE, *_ABORTED, *REVOK*, TIMEOUT; canStartDownload = hasNewAssignment && status ∈ {"", NEWBORN, NEW}. A stuck cloud install (synchronizeStatus=NOK) blocks remote control — cancel endpoint clears it. Every OTA call first re-fetches vehicle-list for codes (could be cached).
13. Retries: journeys 20×600 ms on 5xx; sentry clip poll 40×3 s; charge-plan confirm 8×2 s; heartbeat backoff 30 s→240 s; no generic retry/rate-limit layer elsewhere. Timeouts: TSP client 20 s connect / 30 s read; login UC/TSP/xchanger clients use OkHttp defaults (10 s); push client 20/30 s; GitHub default client.
14. Shares/accept-list keyed by `userId` but unsure whether server wants JWT userId or accountUuid → tries both. Share times may be epoch seconds (<1e11 ⇒ ×1000).
15. RHD/LHD detection is a heuristic regex over vehicle-config; real field unknown. Account-country field names in user/info inferred (TODO 0.2.7).
16. Unverified regions: SEA flagged unverified in table though comment claims a verified login; ME projectId/xchanger/usercenter/message-core segments are guesses; LA usercenter segment unverified.
17. No token refresh; heartbeat + commands keep hammering until 401 clears the token. No auto-relogin despite stored credentials.
18. Dead code to drop: `TspApi.login`, `LoginRequest/LoginResponse`, `inboxUnread`, `parkingSnapshots`, `InboxAuthToken`, `inboxAuthReady`, `ZeekrConst.projectId`, `URL_URL/PROTOCOL_URL/INBOX_URL/UPDATELANGUAGE_URL`, `signAlgo`, legacy device fields, `ShareInvite`'s unused filters. `LOCKER_*` password placeholder `1234` and glovebox/visitor `0000` must be replaced by user PIN.
19. Status poll + every command each send their own heartbeat → many hb calls (stock does similar). Consider coalescing.
20. `SentryAutoArmer`: on car-lock (walk-away or manual) with `autoSentryOnLock`, gets phone location (fresh fix ≤8 s, max age 60 s, balanced power; else last location) and arms `SENTINEL_ON` unless inside any `sentryExclusionZones` circle; **fail-closed** (no location ⇒ don't arm). `isPointInAnyZone` tests car position for proximity exclusion; `phoneZoneStateFast` uses cached location only (1.5 s) returning tri-state.

### Tests present (core/src/test)
* `VinCryptoTest`: invalid key length returns plain VIN; blank VIN returns ""; validate() 16-byte rule.
* `ChargePowerTest`: DC pile power 250 A×480 V = 120 kW (no phases, charging); DC power alone marks charging even if chargerState 0; idle capture (incl. dcChargeIAct −1638) not charging; AC 3-phase = √3·400·16.
* `InboxNotificationMetadataTest`, `CarNotificationCategoryTest`: home parsing, category ids, hint inheritance rules (group types only propagate; message subtypes stay local), classification precedence.
* `SecretsConfigExportTest`, `SignedOutConfigTest`: export blanks password+tokens; sign-out clears account/session/location identity, keeps app secrets/region/calibration/units.
* No tests exist for any signing algorithm (UC HMAC, X-SIGNATURE, overseas, HF) — a rewrite should add golden-vector tests captured from a working build.
