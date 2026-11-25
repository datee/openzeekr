# OpenZeekr — Stock-app config assets & native libraries (rewrite reference)

**What:** static analysis of the config assets and native libraries (`arm64-v8a`) of the official
Zeekr overseas app `com.zeekr.overseas` **3.1.2**, to validate and extend OpenZeekr's clean-room
specs (docs 01 cloud / 02 digital-key).
**Version analysed:** `com.zeekr.overseas` 3.1.2 (base APK assets + arm64 native libs).
**Method:** STATIC ONLY — `file` / `readelf -d` / `nm -D` / `strings` / `od`, every unpacked file
passed as a path argument. Nothing from the APK was executed. All unpacked files treated as
untrusted data.
**Authorised:** reverse-engineering of the user's own app for OpenZeekr interoperability.
**No secrets:** this document records **interface and structure only** — host templates, config
schemas, native symbol/JNI method names, algorithm identifiers, and which lib does what. Where an
embedded key / certificate / secret getter exists, only its **presence and purpose (by name)** is
noted. **No key bytes, no PEM bodies, no secret values are reproduced here.**

Raw tool output kept under `apk_work/native/` and the agent scratchpad; only filtered results are
quoted below.

---------------------------------------------------------------------------------------------------

## 1. Region & host model

Two assets drive region/host construction:

* `assets/host.txt` — the **host-construction template**: `areaType` × `brand` → `suffix` +
  per-generation / per-auth-mode URL **prefixes**. This builds the **xchanger / ECARX "DK-backend"
  (ecloud*) host** — i.e. OpenZeekr's `Region.xchangerHost` / `SecretsConfig.baseUrl` family.
* `assets/urlconfig.properties` — a flat `areaType` × `envType` → **applog** (telemetry) URL table.

> Scope note: `host.txt` governs **only** the `ecloud*` / `xcloudsvc` DK-backend host family. The
> TSP gateway (`*-snc-tsp-api-gw.zeekrlife.com`) and the Azure overseas-app gateways
> (`gateway-pub-*.zeekr.*` / `.zeekrlife.com`) are **not** in `host.txt` and are unaffected by the
> finding below.

### 1.1 Construction rule (from `host.txt`)

```
base = <prefix for (gen, authMode, brand)> + <env infix> + <suffix for (area, brand)>
```
* `envType`: `testing → "-test"`, `staging → "-stage"`, `production → ""` (inserted only where the
  block's `*EnvTrends` flag is true / implied).
* `authMode`: **SingleAuth** (bearer/TLS one-way) vs **MutualAuth** (mTLS, `apis…` prefixes) vs
  **Cert**. `gen1` vs `gen2` = platform generation (ZEEKR EU is **gen2**).
* **Brand resolution:** a `brand` block only overrides the keys it defines; **missing keys (or a
  missing brand block entirely) fall back to that area's `default` block.** The `ZEEKR` brand block
  exists **only under `EU` and `CN`**. For every other overseas area (`APAC`, `NA`, `SA`, `TUR`,
  `UAE`, `RU`) a ZEEKR car therefore builds its DK host from that area's **`default`** block with
  the plain `https://api` / `https://apis` prefix — **there is no `-zk` prefix outside EU/CN.**

### 1.2 Resolved **ZEEKR** DK-backend (xchanger/ecloud) hosts — PRODUCTION

| areaType | ZEEKR block? | SingleAuth (prod) | MutualAuth (prod) | source block |
|---|---|---|---|---|
| **EU**  | **yes (gen2)** | `https://api-zk.ecloudeu.com` | `https://apis-zk.ecloudeu.com` | `EU.ZEEKR` gen2 prefixes `api-zk`/`apis-zk`, suffix `.ecloudeu.com` |
| **APAC** | no → default (gen1) | `https://api.ecloudkr.com` | `https://apis.ecloudkr.com` | `APAC.default`, suffix `.ecloudkr.com` |
| **NA**  | no → default (gen1) | `https://api.ecloudus.com` | `https://apis.ecloudus.com` | `NA.default`, suffix `.ecloudus.com` |
| **SA**  | no → default | `https://tsp-geely-api-sa.xcloudsvc.com` | `https://tsp-geely-apis-sa.xcloudsvc.com` | `SA.default` prod prefix `tsp-geely-api(s)` + `-sa.xcloudsvc.com` (test/stage → `https://api.ecloudsa-test.com`) |
| **TUR** | no → default | `https://tsp-geely-api-tur.xcloudsvc.com` | `https://tsp-geely-apis-tur.xcloudsvc.com` | `TUR.default` + `-tur.xcloudsvc.com` (test/stage → `https://api.ecloudtur-test.com`) |
| **UAE** | no → default | `https://tsp-geely-api-uae.xcloudsvc.com` | `https://tsp-geely-apis-uae.xcloudsvc.com` | `UAE.default` + `-uae.xcloudsvc.com` |
| **RU**  | no → default | `https://tsp-geely-api-ru.xcloudsvc.com` | `https://tsp-geely-apis-ru.xcloudsvc.com` | `RU.default` + `-ru.xcloudsvc.com`; brand `VOLGA` → `https://tsp-yfg-api-ru.volgacars.ru` |
| **CN**  | yes (private) | `https://api.zeekrline.com` | gen1 `tls-api` / `g-apis.xchanger.cn` | `CN.ZEEKR` privateSingleAuth suffix `.zeekrline.com` |

Non-brand `default` **gen2** (reference): EU `apiv2`/`apisv2.ecloudeu.com`; CN `apiv2`/`apisv2.xchanger.cn`.

### 1.3 Resolved applog (telemetry) hosts — PRODUCTION (from `urlconfig.properties`)

`EU https://applog-api.ecloudeu.com` · `APAC https://applog-api.ecloudkr.com` ·
`NA https://applog-api.ecloudus.com` · `SA https://applog-geely-api-sa.xcloudsvc.com` ·
`TUR https://applog-geely-api-tur.xcloudsvc.com` · `UAE https://log-admin-geely-uae.xcloudsvc.com` ·
`RU https://applog-geely-api-ru.xcloudsvc.com`. These **corroborate** the SA/TUR/UAE/RU
"production → `xcloudsvc.com`, test/stage → `ecloud*-test.com`" split used in §1.2.

### 1.4 Cross-check vs OpenZeekr `Region.kt` / doc 01 §1 — `xchangerHost`

| Region | OpenZeekr `xchangerHost` | Authoritative (host.txt §1.2) | Verdict |
|---|---|---|---|
| EU | `https://api-zk.ecloudeu.com` | `https://api-zk.ecloudeu.com` | ✅ **AGREE** (EU ZEEKR gen2 single) |
| SEA (`APAC`) | `https://api-zk.ecloudkr.com` | `https://api.ecloudkr.com` | ❌ **DISAGREE** — APAC has no ZEEKR block; OZ carried EU's `-zk` prefix across. Authoritative = plain `api.ecloudkr.com`. |
| LA | `https://api-zk.ecloudeu.com` | `https://api.ecloudeu.com` | ❌ **DISAGREE** — and OZ's own code comment already records the live `com.zeekr.global` logcat value as `https://api.ecloudeu.com` (no `-zk`). The `-zk` in the Kotlin is wrong by OZ's own evidence. |
| ME | `https://api-zk.ecloudeu.com` (marked uncertain) | `https://api.ecloudeu.com` (if ME rides EU ecloud) | ❌ **DISAGREE** on the `-zk` prefix; same systematic error. |

**Headline finding (NEW):** OpenZeekr applied EU's ZEEKR-specific `api-zk` / `apis-zk` prefix to
**all** regions, but `host.txt` defines the `-zk` (ZEEKR brand) prefix **only for EU and CN**. For
`APAC/NA/SA/TUR/UAE/RU` the stock app resolves the DK-backend host from the area's `default` block
with the plain `api` / `apis` prefix. OZ's own LA live-logcat note (`api.ecloudeu.com`) confirms
this. Recommended correction:

* SEA → `https://api.ecloudkr.com`
* LA → `https://api.ecloudeu.com`
* ME → `https://api.ecloudeu.com` (best-effort; ME ecloud routing still unverified)

Caveats: (a) the exact brand→default fallback is inferred from the `host.txt` structure plus the LA
logcat; confirming against the stock dex host-builder would make it certain. (b) These are the
`xchangerHost` values only — EU's `zeekrlife.com` TSP gateway and the Azure gateways are a separate
host family and are **not** affected. (c) All host fields remain user-overridable in OZ Settings, so
a per-install override fixes a wrong default without a rebuild.

---------------------------------------------------------------------------------------------------

## 2. Other config assets (`base/assets/`)

Inventory of assets carrying hosts / endpoints / feature-flags / region / keys. Pure animation/UI
JSON (Lottie `*_anim_*`, `appbar_config_*`, `car_animation_*`, `ble_animation_*`) and HERE map
resources (`*.ms`, `*.obj`, `location_indicator_*`) are skipped.

| Asset | Purpose / schema | Relevance |
|---|---|---|
| `host.txt` | DK-backend host-construction template (§1). JSON: `envType{}` + `areaType{ <AREA>{ <brand>{ suffix, gen{1,2}{Mutual,Single}AuthPrefix, …CertPrefix, *EnvTrends } } }`. | **§1 — primary** |
| `urlconfig.properties` | `urlConfig` = JSON array `[{areaType, envType, url}]` of **applog** telemetry hosts (§1.3). | region host cross-check |
| `grs_sdk_server_config.json` | **Huawei GRS** (Global Routing Service) bootstrap: `grs_base_url[]` = `grs.dbankcloud.{com,cn,asia,eu}` + `grs.platform.dbankcloud.ru`; `grs_query_endpoint_{1.0,2.0}`; `grs_query_timeout`. Used by HMS (Push/Scan/Maps) to resolve regional service endpoints at runtime. | HMS dependency only; not TSP |
| `grs_sdk_global_route_config_mlkit.json` | GRS route table for HMS **ML Kit** (barcode/scan). | HMS only |
| `grs_sp.bks`, `hmsincas.bks`, `hmsrootcas.bks` | BKS keystores: HMS intermediate/root CA trust stores + GRS shared-prefs store. | HMS TLS trust |
| `ca.pem` | `LightShowCa` — zeekrlife internal CA for the light-show feature (per earlier read). | light-show only |
| `geely_{prod,qa}_{cn,eu}_{1..5}.pem.enc`, `lotus_{prod,…}_*.pem.enc` | **Encrypted** PEM client certs (5 each per env/region/brand), raw DER-ish ciphertext (not plaintext PEM). Almost certainly the **gen1 MutualAuth (mTLS) client-cert bundles** pinned for `apis…` hosts. | mTLS; **encrypted** — presence only |
| `key1.enc`, `key2.enc` (129 B each) | Encrypted key blobs paired with the `*.pem.enc` certs. | presence only |
| `ec_dt.lic`, `kwpt.lincense` (sic) | License blobs: `ec_dt.lic` (EC/detect model licence), `kwpt.lincense` = **KiwiSec KwProtect** runtime licence (pairs with `libKwProtectSDK.so` §3). | anti-tamper licence |
| `filename.txt` | ProGuard obfuscation dictionary (reserved-keyword names `ssdo`, `ssif`, …). Confirms managed code is ProGuard-obfuscated. | build hygiene |
| `discover.json`, `discoverPageEn.json`, `discoverPageHe.json` | "Discover" content-feed layout (EN + **Hebrew** = Israel market). No hosts. | content UI |
| `dealerListEn.json`, `dealerListHe.json` | Static dealer directory (EN/Hebrew). | content UI |
| `ft_mcc_mnc_mini.json` | MCC/MNC → carrier/country lookup table (SIM/eSIM region inference). | locale |
| `SettingsConfig.json`, `ShareConfig.json` | **CN** webview browser menu (复制链接/刷新/浏览器) + share targets (微信/朋友圈/微博). CN-only, dead overseas. | ignore |
| `demo1-3.html`, `jsbridge_test.html` | Webview JS-bridge test pages. | dev scaffold |
| `ZEEKR_OTA_20240511.bin` | Bundled sample/seed OTA payload blob. | not an endpoint |
| `001-em`, `bx1e-em` (+ `.manifest`) | **Unity AssetBundles** — `UnityFS` / Unity **2022.3.62f2** (header `UnityFS…5.x.x…2022.3.62f2c1`). Energy-model (`-em`) bundles keyed by vehicle code (`bx1e` = a model code). `.manifest` = standard Unity `ManifestFileVersion`/`CRC`/`Hashes`/`ClassTypes` sidecar. Loaded by `libunity.so`/`libil2cpp.so`. | Unity 3D car / energy-flow viz |
| `bin/Data/**` | IL2CPP payload: `data.unity3d`, `Managed/Metadata/global-metadata.dat`, `boot.config`, `ScriptingAssemblies.json`, `RuntimeInitializeOnLoads.json`. | Unity runtime (§3/§5) |

---------------------------------------------------------------------------------------------------

## 3. Native libraries (`lib/arm64-v8a/`)

All ELF 64-bit aarch64. `libHttpSecretKey.so`, `libdk-ndk.so`, `libiwallca.so` ship **with
`debug_info` (not stripped)** → rich static symbols. The rest are stripped but export dynamic
symbols / `Java_*`.

| lib | Purpose | Recovered symbols / algorithms (interface only) | Relevance to rewrite |
|---|---|---|---|
| **libHttpSecretKey.so** (1.8 MB) | **HTTP signing-key provider** for the ECARX/"haohan" HTTP SDK. Stores & vends the request-signing secret; it does **not** compute the HMAC itself. | JNI: `com.haohan.module.http.encrypt.HttpSecretKey.getSecretKey()` / `.setSecretKey()`; `com.haohan.common.security.HHSecurity.getUtdidKey()`. Strings: only `secretKey`, `HttpSecretKey.cpp` — **no** `HMAC`/`SHA`/`AES`/`base64` strings. | Confirms doc 01 §3.2: X-SIGNATURE HMAC-SHA256 is computed in **managed code**; native only hands over the key. `setSecretKey` = runtime region-swap hook. |
| **libsecret.so** (353 KB) | **Per-region TSP secret provider** (`com.zeekr.sdk.security.so.NativeSecretLib`). | JNI: `getTSPSecretValue(region,…)`, `getGUANCEToken` (Guance/观测云 APM), `getPrivatePrivacyPurposeId`, `getTermsAndUsePurposeId`. (Strings swamped by statically-linked libc++ demangler.) | **Directly confirms** doc 01 §1.3 `NativeSecrets.*(extractorRegion)` via `getTSPSecretValue`; the region arg selects the baked EU/EM/SEA secret set. |
| **libComUtil.so** (270 KB) | **Digital-key SDK embedded config + crypto material getter** (`com.digitalkey.jnilib.JniUtils`). | JNI getters (all `*Base64`): `getAESKey`, `getAESIv`, `getBleAuthKey`, `getSdkPublicKey`, `getSdkPrivateKey`, `getTspPublicKey`, `getTspSdkPublicKey`, `getAppSecret`, `getAppSecretKey`, `getAccessTokenKey`, `getRefreshTokenKey`, `getCNBaseUrl`, `getCNHttpsUrl`, `getEUBaseUrl`, `getEUHttpsUrl`, `getDefaultAppId`, `getDefaultEnvType`, `getDefaultAccept`, `getSPFileName`, plus `getAccesskeyId`/`getAccesskeySecret`/`getAl{Endpoint,Logstore,Projectname,Source}` (= **Aliyun Log Service / SLS** logging config). | **NEW.** The DK SDK's EU/CN base+https URLs, BLE auth key, SDK keypair and TSP public keys are all native-baked here. Values **not** recorded. Feeds doc 02. |
| **libdk-ndk.so** (2.5 MB) | **BLE digital-key native** (`com.base.bluetooth.dk.*`): key/IV/CMAC material, pairing-packet builders, and the DK **certificate chain**. | JNI: `DKBaseJNI.{getKeyJNI,getIvJNI,getCmacKeyJNI,getSecretKeyJNI,getDefaultSecretKeyJNI,getDkDigestJNI,getGidJNI,getIdJNI}`; `BasePackerJNI.{getPairDataJNI,getNewPairDataJNI}`; `DkCipherManagerJNI.{getRoot,getSubRoot,getEcu{,Zk}{EU,CN}}{Test,Prod}JNI`. Embedded X.509 certs visible (subjects incl. `…ZK ECU Issuing … CA-CN`, `… Root CA`) using **EC P-256 / prime256v1** (OID `1.2.840.10045.2.1` + `…3.1.7`). | **NEW/confirms doc 02.** DK = **AES + AES-CMAC** session crypto over an **ECDSA P-256 cert chain** (Root → Sub-Root → ECU), split EU/CN × Zk/non-Zk × prod/test. Cert **presence** noted; **no bytes**. |
| **libiwallca.so** (6.2 MB) | **Digital-key CA / soft secure-element** — Baidu **"SVKD 2.0"** IWall Security Suite (`com.iwall.security.SecuritySuite`; build path `…/JiliProjects/…/BaiduSVKD2.0/device/IWallSecuritySuite.cpp`, OpenSSL 1.1.1w). | JNI: `init`, `initCertificates`, `generateApplyCrtByCSR`, `import/exportCertificate`, `getRootCert`, `certsCheckWith{CRL,OCSP,Chain}`, `generateECCTempKeyPair`/`destroyECCTempKeyPair`, `ecc{Encode,Decode}PublicKey`, `ecdhReceiver`, `generateSymmKey`, `symmCompute(Ex)`, `cmacCompute`, `sm3Compute`, `asymm{Encrypt,Decrypt}`, `sign`/`verifyByCertificate`, `exportSSL{Key,Chain}`, secure file store `read/write/delete/removeFiles(Ex)`, `modifyUserPIN`/`unlockPIN`, `registerLicense`, `sdkDeviceID`, `sdkVersion`. | **NEW.** The CCC-style secure channel + device-cert custody behind the digital key: **ECDH (P-256) key agreement, ECC keypairs, AES (symmCompute), AES-CMAC, SM3, X.509 w/ OCSP+CRL**, PIN-gated key store. Pairs with `libdk-ndk`. Feeds doc 02. |
| **libkadp.so** (1.2 MB) | **KiwiSec anti-tamper / DEX hardening** (`KiwiSecDexHardening`, `com/kiwisec/crash/CrashUtils`, `KWS_MAIN_APP`, `ProtectStatus`). | Exports `JNI_OnLoad`/`JNI_OnUnload` (dynamic registration). Strings: `/system/lib64/libfrida-gadget.so`, `/proc/self/maps`, `ro.yunos.version`, `mprotect` → **anti-Frida / anti-debug / root-&-emulator detection + DEX decrypt**. | **Explains why static key extraction fails and why Frida is needed** — and actively detects Frida. |
| **libKwProtectSDK.so** (2.9 MB) | **KiwiSec runtime white-box protection.** | `JNI_OnLoad`, `init_runtime_protect`, `mprotect`. (licence = `assets/kwpt.lincense`.) | Likely **white-boxes the signing keys** vended by `libHttpSecretKey`/`libsecret` — static byte-level key recovery is expected to fail; runtime (Frida) capture is required. |
| **libkwsdataenc.so** (1.1 MB) | **KiwiSec white-box data encryption.** | `JNI_OnLoad`, `init_runtime_data`, `mprotect`. | White-boxed at-rest data; same implication. |
| **libenv.so** (200 KB) | Small JNI helper, dynamic registration only (clang 19 toolchain). No identifying strings beyond `libenv.so`. | `JNI_OnLoad` only; symbols hidden. | Purpose not recoverable statically (likely env/integrity or config helper) — **needs a disassembler.** |
| **libkadp/libKwProtect/libkwsdataenc** together | = the **KiwiSec obfuscation/white-box/anti-tamper layer**. | — | The reason the stock keys cannot be lifted by `strings`/`nm`; OpenZeekr's user-supplied-secret model (Frida extraction per region) is the correct approach. |
| **libscannative.so** (2.6 MB) | **Huawei HMS ScanKit** QR/barcode (OpenCV) — `com.huawei.hms.scankit.util.OpencvJNI`. | JNI: `QRCornerDetect`, `multiBarcodeDetect`, `QuadFitting`, `adaptiveBinary`, `imageResize/Rotate`, `removeMoirePattern`, `sharpen`, `setModel`. | QR scanning (pairing-code / login-QR capture). Not crypto. |
| **libmmkv.so** (717 KB) | **Tencent MMKV** encrypted key-value store. | Exports `encode*`/`decode*`, `cryptKey`, `checkReSetCryptKey`, `backupAll`… | Local persistence (possibly encrypted). Informational. |
| **libheresdk.so** (31 MB) | **HERE Maps** SDK (navigation/geoviz). Huge JNI surface. | — | Maps only; out of scope. |
| **libunity.so** (16 MB) / **libil2cpp.so** (19 MB) / `lib_burst_generated.so` / `libdatastore_shared_counter.so` | **Unity 2022.3.62f2 + IL2CPP** runtime for the 3D car model & energy-model (`-em`) bundles. | — | 3D viz only; C# logic recoverable via Il2CppDumper (§5), not attempted. |
| `libc++_shared.so`, `libsmartlog.so`, `libzlogan.so`, `libft_native_*`, `libimage_processing_util_jni.so`, `libsurface_util_jni.so`, `libmain.so` | STL; smart/zlog logging; CameraX image/surface JNI; Flutter `libmain` shim. | — | Support libs. |

---------------------------------------------------------------------------------------------------

## 4. JNI ↔ Java bridge — native-backed operations

`Java_*` exports recovered statically (dynamic `RegisterNatives` libs — kadp/KwProtect/kwsdataenc/
env/mmkv — hide their names and are not listed here). This maps exactly which Java classes call into
native code and for what.

**Signing / secrets**
```
com.haohan.module.http.encrypt.HttpSecretKey      getSecretKey() / setSecretKey()        [libHttpSecretKey]
com.haohan.common.security.HHSecurity             getUtdidKey()                           [libHttpSecretKey]
com.zeekr.sdk.security.so.NativeSecretLib          getTSPSecretValue(), getGUANCEToken(),  [libsecret]
                                                   getPrivatePrivacyPurposeId(), getTermsAndUsePurposeId()
```

**Digital key — config & crypto material**
```
com.digitalkey.jnilib.JniUtils                     get{AESKey,AESIv,BleAuthKey,SdkPublicKey,SdkPrivateKey,  [libComUtil]
                                                   TspPublicKey,TspSdkPublicKey,AppSecret,AppSecretKey,
                                                   AccessTokenKey,RefreshTokenKey,CNBaseUrl,CNHttpsUrl,
                                                   EUBaseUrl,EUHttpsUrl,DefaultAppId,DefaultEnvType,
                                                   DefaultAccept,SPFileName,AccesskeyId,AccesskeySecret,
                                                   Al{Endpoint,Logstore,Projectname,Source}}Base64()
```

**Digital key — BLE protocol & cert chain**
```
com.base.bluetooth.dk.bean.DKBaseJNI               get{Key,Iv,CmacKey,SecretKey,DefaultSecretKey,          [libdk-ndk]
                                                   DkDigest,Gid,Id}JNI()
com.base.bluetooth.dk.business.client.packer.BasePackerJNI  getPairDataJNI(), getNewPairDataJNI()          [libdk-ndk]
com.base.bluetooth.dk.cipher.DkCipherManagerJNI    get{Root,SubRoot}{Test,Prod}JNI(),                      [libdk-ndk]
                                                   getEcu{,Zk}{EU,CN}{Test,Prod}JNI()
```

**Digital key — CA / secure element** (`com.iwall.security.SecuritySuite`, `libiwallca`): full list
in §3 (init, cert lifecycle, ECDH/ECC, AES/CMAC/SM3, sign/verify, PIN-gated secure file store).

**Scanner** (`com.huawei.hms.scankit.util.OpencvJNI`, `libscannative`): QR/barcode image ops (§3).

Takeaway for a rewrite: the **only** native-backed operations that matter for cloud interop are
**(a)** the signing-secret vend (`HttpSecretKey.getSecretKey` / `NativeSecretLib.getTSPSecretValue`)
— the HMAC itself is managed — and **(b)** the entire **digital-key** stack (`JniUtils` config +
`DKBaseJNI`/`BasePackerJNI`/`DkCipherManagerJNI` BLE crypto + `SecuritySuite` CA/SE). Everything
else is maps / scanning / logging / UI.

---------------------------------------------------------------------------------------------------

## 5. What this confirms vs docs 01/02, and what still needs more tooling

**Confirms (doc 01 — cloud/signing):**
* X-SIGNATURE is HMAC-SHA256 in **managed code**, keyed by a native-vended secret — `libHttpSecretKey`
  has **no** HMAC/SHA/AES code, only `getSecretKey`/`setSecretKey`. (doc 01 §3.2) ✅
* The per-region TSP secret comes from `NativeSecretLib.getTSPSecretValue(region)`; region arg
  selects the baked set — matches doc 01 §1.3's `NativeSecrets.*(extractorRegion)` and the
  Frida-confirmed `getTSPSecretValue`. ✅
* Keys are **white-boxed / anti-tamper-protected** (KiwiSec `libKwProtectSDK` + `libkwsdataenc` +
  `libkadp` with explicit Frida/debug/root detection). This is why static key extraction fails and
  why OZ's "user supplies region secrets via runtime extraction" model is the right one. ✅ (NEW: names the exact protector.)

**Corrects (doc 01 §1 / `Region.kt`):**
* `xchangerHost` for SEA/LA/ME should use the **plain `api`** prefix (`api.ecloudkr.com`,
  `api.ecloudeu.com`, `api.ecloudeu.com`), **not** `api-zk` — the `-zk` ZEEKR prefix exists only for
  EU/CN in `host.txt`. (§1.4) ❗

**Confirms/extends (doc 02 — digital key):**
* DK crypto = **ECDSA/ECDH on P-256 (prime256v1)** cert chain (Root → Sub-Root → ECU, split
  EU/CN × Zk × prod/test) + **AES-CMAC** session keys — visible in `libdk-ndk` symbols and embedded
  certs. The CA/secure-element side (`libiwallca` = Baidu SVKD 2.0) adds ECDH key-agreement, ECC
  temp keypairs, AES, CMAC, SM3, and X.509 with OCSP/CRL, behind a PIN-gated secure file store. This
  is a **CCC/ICCE-style** digital-key design. Cross-check against doc 02's clean-room DK spec.

**Still needs a disassembler / dumper / live capture (NOT attempted here, static-only):**
1. **Key/secret VALUES** — intentionally not extracted; white-boxed. Require **Frida** at runtime
   (OZ's existing `zeekr_key_extractor` approach). The embedded DK certs in `libdk-ndk`/`libiwallca`
   are present but were not dumped.
2. **`libdk-ndk` / `libiwallca` algorithm wiring** — exact KDF/HKDF, nonce/opcode layout, GATT
   service/characteristic UUIDs, and CMAC input framing need IDA/Ghidra; strings were dominated by
   the statically-linked C++ demangler. doc 02's BLE opcode/GATT details can't be confirmed from
   symbols alone.
3. **`libenv.so`** purpose — dynamic JNI registration, no identifying strings; needs disassembly.
4. **Dynamically-registered natives** (kadp/KwProtect/kwsdataenc/mmkv) — method names hidden behind
   `RegisterNatives`; recover via runtime hook if ever needed.
5. **Managed (C#) Unity logic** — `global-metadata.dat` (5 MB, header obfuscated, `file`→`data`) +
   `libil2cpp.so` could be run through **Il2CppDumper** to recover C# method names for the 3D/energy
   models. Not attempted; low interop value.
6. **`host.txt` brand→default fallback** — the brand-resolution rule in §1.1 is inferred from the
   template plus the LA logcat; the stock **dex** host-builder would make §1.4 certain.
