# openzeekr — BLE Digital Key, Proximity, RPA and Wear Key-Sharing: Rewrite Spec

Source of truth: `core/src/main/java/com/openzeekr/app/ble/**`, `core/.../app/wear/**`,
`wear/src/main/java/com/openzeekr/wear/**`, `app/src/main/java/com/openzeekr/app/wear/**`,
`core/src/test/java/com/openzeekr/app/ble/**`, README.md, CHANGELOG.md. The spec covers protocol
and behaviour only and leaves the UI out. Every constant is copied from code. "Stock" means the
official Zeekr Android app that was reversed (smali/Frida). All multi-byte integers are **big-endian**
unless noted.

Notation: `‖` = concatenation, `[a:b]` = byte slice (b exclusive).

---

## 1. Provisioning (cloud enrolment of the BLE key)

### 1.1 Local identity (`DkIdentity`)

Stored in its own EncryptedSharedPreferences file **`openzeekr_dk_identity`** (MasterKey AES256_GCM;
pref-key AES256_SIV, pref-value AES256_GCM). Process-wide singleton.

| pref key | content | created |
|---|---|---|
| `device_id` | 64 lowercase hex chars = 32 random bytes (matches the stock `getDeviceID` format) | lazily on first read, never rotates until `wipeAll` |
| `priv` | base64(NO_WRAP) PKCS#8 DER of the long-term **P-256 (secp256r1)** private key | lazily on first `keyPair()` |
| `pub` | base64 X.509 SubjectPublicKeyInfo DER of the public key | same |
| `cert` | create-app-certificate `data.cert` (base64 DER leaf, no PEM armour) | provisioning |
| `dk_id` | the long numeric cloud `dkId` (used for key-info / remove-one-key) | provisioning |
| `book_id` | the short hex `bookId` (e.g. `8000a5cb`). **This is the BLE `dkID`.** | provisioning |
| `digital_key` | key-info `digitalKey` (base64), sent in BLE 0x010B | provisioning |
| `cmac_key_cert` | key-info `cmacKeyCert` (hex), the ECIES envelope for the RPA CMAC key | provisioning |
| `coef_small` | `coefSmallParam` (hex) | provisioning |
| `coef_big` | `coefBigParam` (hex) | provisioning |
| `mobile_code` | `mobileCode` (hex, usually 3 bytes, may be `FFFFFF`) | provisioning |
| `vin` | 17-char VIN | provisioning |

The private key is generated in software and stays exportable, so it is not bound to the device
Keystore. That is deliberate: it is what allows cloning the identity to the watch (§9).
`isProvisioned` = `cert != null && digital_key != null`.

- `clearProvisioned()` removes cert, dk_id, book_id, digital_key, cmac_key_cert and coef_small. It
  keeps the keypair and deviceId. **Bug:** it does NOT clear coef_big, mobile_code or vin.
- `wipeAll()` = `prefs.clear()`, which removes the keypair and deviceId too.
- CLONE_KEYS (exported to the watch) = device_id, priv, pub, cert, dk_id, book_id, digital_key,
  cmac_key_cert, coef_small, vin, coef_big, mobile_code.

**CSR** (`buildCsrPem`): PKCS#10, SHA256withECDSA, subject exactly
`C=CN,ST=ZheJiang,L=Hangzhou,O=ECARX,OU=CloudDept,CN=<deviceId[0:8]>`, PEM armoured
`-----BEGIN CERTIFICATE REQUEST-----`, 64-char lines. The server replaces CN with the deviceId.
The full DN is required: a partial subject gets a 400.

**Cloud request signature** (`signDkMessage`): `base64_nowrap( ECDSA_SHA256_DER( priv, ascii(userId ‖ deviceId ‖ vin) ) )`.
Every signed DK call uses this same message, re-signed for each call (ECDSA is randomised).

### 1.2 Transport

- Base URL = TSP gateway `ConfigStore.current().baseUrl`. The EU default is
  `https://eu-snc-tsp-api-gw.zeekrlife.com` (`SecretsConfig.baseUrl`).
- The OkHttp chain reuses the app's `HeaderInterceptor(store)` + `SignInterceptor(store)`. Request
  signing, the bearer token and the X-VIN header come from there and are outside this scope. Body
  logging is BASIC only while debug HTTP logging is on, with sensitive values scrubbed.
- JSON: `ignoreUnknownKeys=true, encodeDefaults=true, isLenient=true`. **encodeDefaults is
  required**: stock sends `dkType` and `type` in key-list.
- Success is `code == "000000"`. Envelope: `{code, msg, data}`.

Path prefixes:
- `CERT = ms-tsp-dkbs-geely/api/v1.0/app/certificatecenter`
- `DKC  = ms-tsp-dkbs-geely/api/v1.0/app/digital-key-center`

| # | Method & path | Body / query | Response `data` |
|---|---|---|---|
| A | `POST CERT/create-app-certificate` | `{deviceId, csr}` (csr = PEM string) | `{id?, cert}` (cert = base64 DER) |
| B | `POST DKC/key-list` | `{deviceId, signature, dkType:2, type:2}` | `[KeyItem]` |
| C | `POST DKC/create-owner-blu-key` | `{deviceId, proprietary:"", signature}` | `KeyItem` |
| D | `POST DKC/create-share-key` | same as C (for non-owner accounts) | `KeyItem` |
| E | `POST DKC/share-key` | `{deviceId, dkId, signature}`. Accepts/binds a shared key to this device | any |
| F | `POST DKC/repush-key-to-vechile` (sic, misspelled in the real API) | `{deviceId, dkId, signature}` | any |
| G | `GET DKC/key-info` | `?deviceId&dkId&mobileBrand&mobileModel&signature` | `KeyInfoData` |
| H | `GET DKC/loop-key-status` | `?dkId&syncType=1` | `{dkStatus}` |
| I | `GET DKC/phonecoef` | `?mobileBrand&mobileModel` (coefHash omitted, as stock does) | `DemarcateData` |
| J | `POST DKC/remove-one-key` | `{deviceId, dkId, signature}` | any |
| K | `POST DKC/sync-key-list` | same bean as key-list. Declared but **not called** by provisioning; it would move dkStatus 3 to 5 | any |
| L | `GET DKC/key-status` | `?dkId&syncType`. Deprecated, unused | any |
| M | `GET DKC/pairing-code` | none; car chosen by X-VIN header | `{phonePassword}` (CCC/Apple-Wallet pairing code, dev probe) |

`KeyItem = {dkId, bookId?, vin?, deviceId?, dkStatus?, shareStatus?, keyType?, dkType?, ownerId?, userId?, approachUnlock? (1/0), walkAwayLock? (1/0)}`
`KeyInfoData = {dkId?, bookId?, digitalKey?, cmacKeyCert?, phoneCoef?, mobileCode?, coefSmallParam?, coefBigParam?, coefHash?}`
`DemarcateData = {coefBigParam?, coefSmallParam?, mobileCode?, coefHash?, phoneCoef?}`

The phone identity sent as mobileBrand/mobileModel is `ZeekrConst.XCHANGER_DEVICE_MANUFACTURE="google"`
and `XCHANGER_DEVICE_MODEL="Pixel 7"`. The app spoofs a Pixel 7, because a key minted under an
unsupported model (Pixel 6a on a 7GT) gets stranded at dkStatus 6.

dkStatus values seen in code: 1 CREATED, 2 SYNCED, 3 AUTHED (ready for BLE first-pair), 4 AUTH_FAIL,
5 ACTIVATED, 6 half-created/stuck, 11 broken. dkType 2 = Bluetooth (key technology, not owner tier).

### 1.3 Provisioning algorithm (`DkProvisioning.provision(owner)`)

```
require cfg.userId, cfg.vin
deviceId = identity.deviceId
sig() = signDkMessage(userId, vin)                       # fresh per call

# Step CERT
repeat up to 4:
    try resp = A(deviceId, buildCsrPem()); cert = resp.data.cert or error; break
    catch HTTP 401: delay 1500 ms; continue     # 401 code 079021 = "account logged in elsewhere"
                                                # (the stock app is active; one active device per account)
    catch other HTTP: throw
if no cert: fail("close / log out of the Zeekr app on the other phone")

# Step KEY_LIST
kl = B(deviceId, sig(), dkType=2, type=2); require code 000000   (061203 = signature/cert/userId mismatch)
broken = first entry with dkStatus in {6,11} AND entry.deviceId == deviceId
if broken:                                  # repair a stranded key
    try J(deviceId, broken.dkId, sig())     # failure ignored
    delay 1500 ms
    list = B(...).data
else list = kl.data
entry = owner ? (first with dkType==2 ?: first) : first

# Step BIND
if entry == null:                           # no key yet, so mint one
    resp = owner ? C : D, body {deviceId, proprietary:"", signature:sig()}
           retried on HTTP 429 (gateway 00A29) up to 4 attempts, 5000 ms apart, re-signing each time
    if resp.data: dkId,bookId = resp.data
    elif resp.code == "036902":             # "already activated": a 429'd create actually succeeded
        re-read key-list; adopt (first dkType==2 ?: first) or fail
    else fail   (079001 = not authorized: a non-owner used the owner endpoint)
else:
    dkId,bookId,shareStatus = entry; boundToUs = entry.deviceId == deviceId
    if !owner:
        if !boundToUs: E(deviceId,dkId,sig()) (failure logged, continue); pollCarSync(dkId)
        elif dkStatus in {1,2,4}: F(deviceId,dkId,sig()); if ok: pollCarSync(dkId)
        else (3 or 5): download only. Never call sync-key-list/repush here: it moves 3 to 5 and the
             car then answers 0x1010 on BLE.
    (owner with an existing entry: download only)

# Step KEY_INFO (digitalKey is generated asynchronously after binding)
repeat attempt 1..6:
    ki = G(deviceId, dkId, "google", "Pixel 7", sig()); d = ki.data or fail
    if d.digitalKey non-blank: break
    delay 2000 ms
fail if digitalKey blank

# Step 5 phonecoef (best effort)
demarcate = I("google","Pixel 7")
pick(a,b) = a if non-blank else b ?: ""
identity.saveProvisioned(cert, dkId, bookId ?: d.bookId ?: "", d.digitalKey, d.cmacKeyCert ?: "",
    pick(d.coefSmallParam, dem.coefSmallParam), vin, pick(d.coefBigParam, dem.coefBigParam),
    pick(d.mobileCode, dem.mobileCode))
ble.forgetCertPin(vin)          # a new key means re-pin the vehicle cert on the next handshake (§4.6)
ble.setCredential(identity.credential())
```

`pollCarSync(dkId, timeout=30000)`: call H every 2000 ms until dkStatus is 3 or 5. On timeout it
logs a warning and does **not** fail; BLE may then return 0x0105.

State machine exposed: `IDLE, CERT, KEY_LIST, BIND, KEY_INFO, DONE, ERROR` plus a message.

### 1.4 Revocation (`removeKey`)

```
dkId = credential.cloudDkId (long numeric)
if dkId && userId && vin:
    r = J(deviceId, dkId, sig()); if r.code != 000000: FAIL and keep everything local
        # the car forgets the key only after a cloud revoke, and that revoke needs this local key
else: skip cloud (local-only key)
ble.disconnect(); identity.wipeAll(); ble.clearCertPins()
```
The watch copy is purged separately by the caller (§9.4).

### 1.5 Passive state read (`passiveState`)

key-list, then our entry (deviceId match, else first) gives `(approachUnlock==1, walkAwayLock==1)`.
If both fields are null the result is null, and the UI keeps its local mirror.

### 1.6 Runtime credential (`DkCredential`)

Built from the prefs by `DkIdentity.credential()`. **Name clash:** `DkCredential.dkId` holds the
**bookId**, and `cloudDkId` holds the long dkId.

| field | derivation |
|---|---|
| `dkCertDer` | base64-decode(cert) |
| `dkPrivateKey` | PKCS#8 parse of priv |
| `digitalKey` | base64-decode(digital_key) |
| `cmacKeyCert` | hex-decode |
| `coefSmall`, `coefBig`, `mobileCode` | hex-decode |
| `dkIdBytes` | hex-decode(bookId), 4 bytes (e.g. `80 00 a6 af`) |
| `phoneId8` | hex-decode(deviceId)[0:8], zero-padded |
| `phoneType3` | mobileCode[0:3], zero-padded (FFFFFF is sent as-is, like stock) |
| `bigCalibHash4` | SHA256(coefBig)[0:4], or 4 zero bytes if coefBig is empty |
| `smallCalibHash4` | SHA256(coefSmall)[0:4], or zeros if empty |

---

## 2. BLE transport

### 2.1 Identifiers

| item | value |
|---|---|
| DK GATT service (**not advertised**) | `02362AFF-CF3A-11E1-EFDE-0002A5D5C51B` |
| ch1 write (phone→car) | `02362A10-CF3A-11E1-EFDE-0002A5D5C51B` |
| ch1 notify (car→phone) | `02362A11-CF3A-11E1-EFDE-0002A5D5C51B` |
| ch2 write | `02362A12-CF3A-11E1-EFDE-0002A5D5C51B` |
| ch2 notify | `02362A13-CF3A-11E1-EFDE-0002A5D5C51B` |
| CCCD | `00002902-0000-1000-8000-00805f9b34fb` |
| Advertised 16-bit service UUID | `0xFDFD` (`0000fdfd-0000-1000-8000-00805f9b34fb`). Shared by every Zeekr, so not unique per car |
| Advertised manufacturer company id | `0x06FE` (bytes `fe 06` LE in the AD) |
| Advertised name | contains `zeekr` (case-insensitive), e.g. `Zeekr<vin-suffix>`; often missing screen-off |

The car uses a **Resolvable Private Address** that rotates, together with the broadcast-random
(default about 15 min). Never `getRemoteDevice(mac)`: Android treats it as a PUBLIC address and the
connect times out with status 147. Always connect a `BluetoothDevice` obtained from a scan result.

### 2.2 Broadcast-random (needed for the handshake)

Walk the raw advert AD structures `[len][type][payload…]`. The DK block is `len == 0x15 && type == 0xFF`.
`packet = record[i+2 : i+1+len]` (20 bytes after the type byte; this includes the 2-byte company id).
`cryptedId = packet[8:20]`, and **`broadcastRnd = packet[12:20]`** (8 bytes). It can arrive in a
different PDU from the name/UUID, so cache it per MAC during a scan and only connect once a MAC
both matches and has an rnd.

### 2.3 Scanning

- Foreground/demand scan: `SCAN_MODE_LOW_LATENCY`, immediate delivery (no `setReportDelay`, because
  batched results never flush to a dozing app screen-off). Timeout `SCAN_TIMEOUT_MS = 20000`.
- Filters: OR of `ScanFilter(serviceUuid=0xFDFD)` and `ScanFilter(manufacturerData id=0x06FE, data=[])`.
  An **unfiltered** scan runs only when `diagnostic=true` AND the screen is interactive, because
  AOSP parks unfiltered scans screen-off. Diagnostic mode logs every advertiser with name, UUIDs,
  service-data keys, mfr ids and raw bytes.
- Software match (any one): name contains "zeekr"; service UUID equals the DK service or 0xFDFD;
  service-data key equals either; mfr data has 0x06FE. Then require `rndByMac[addr]`. Once
  `state != SCANNING`, ignore later adverts. This guard prevents a double connectGatt and the
  resulting status 133.
- On scan timeout: if `passiveListening`, emit `demandScanMiss` and fail with "We'll keep watching…".
  Otherwise fail with "Car not in range. Wake it…".

### 2.4 Hardware-offloaded presence scan (PendingIntent)

`armPresenceScan(mode)`: `startScan(carScanFilters, settings, PendingIntent)` delivered to
`BleScanReceiver`, action `com.openzeekr.app.ble.PRESENCE_SCAN_RESULT`, request code `0x2ee5`,
`FLAG_MUTABLE` on API 31+. Settings: scanMode per mode; callbackType `FIRST_MATCH | MATCH_LOST`;
matchMode per mode; `MATCH_NUM_ONE_ADVERTISEMENT`.

| PresenceMode | scanMode | matchMode | used when |
|---|---|---|---|
| BACKGROUND | LOW_POWER | STICKY | always-on fallback (no motion detection) |
| WALKING | LOW_LATENCY | AGGRESSIVE | first 5 min of a walk |
| LONG_WALK | BALANCED | AGGRESSIVE | still walking after 5 min |

Re-arming in a different mode keeps `carInRange`. A fresh arm resets `carInRange=false`.
FIRST_MATCH sets `carInRange=true`; MATCH_LOST clears it. A controller error (EXTRA_ERROR_CODE != -1)
triggers `onPresenceScanDropped()`, which disarms so it can be re-armed, followed by
`ProximityService.notifyPresenceLost`.

`BleScanReceiver` on FIRST_MATCH: `onPresenceFound()`. If the link is CONNECTING, CONNECTED or
SESSION_READY, do nothing. Otherwise take a 30 s self-expiring PARTIAL_WAKE_LOCK
(`openzeekr:presence-engage`), call `primeFromPresence(results)` (strongest result with an rnd
becomes lastDevice/lastRnd), then `ProximityService.notifyPresent(ctx, mac)`. If the foreground
service start is refused, call `ble.engageFromPresence(mac)` in-process.

`engageFromPresence(mac)`: ignored while CONNECTING, CONNECTED or READY. If SCANNING, stop the
active scan and set IDLE (pre-empting a starved screen-off scan). Then `reconnectLast()`, falling
back to `connect(null)`.

### 2.5 Connect state machine (`DkBleManager`)

States: `IDLE, SCANNING, CONNECTING, CONNECTED, SESSION_READY, ERROR`.

```
connect(mac?, diagnostic=false):
  if handshake backoff active: return
  if state in {SCANNING,CONNECTING,CONNECTED,SESSION_READY}: return     # idempotent
  require adapter enabled
  if mac matches cached lastDevice and reconnectLast(): return
  startScan()

reconnectLast():  # scan-free
  needs lastDevice, resting state, and cache age <= CACHE_MAX_AGE_MS = 600000 (10 min)
  advBroadcastRnd = lastRnd; connectingFromCache = true; state = CONNECTING; connectDevice(dev)

connectDevice(dev):
  if gatt != null: return                 # hard dedupe; never two GATT clients
  gatt = dev.connectGatt(ctx, autoConnect=false, cb, TRANSPORT_LE)
  watchdog: after CONNECT_TIMEOUT_MS = 12000, if still CONNECTING: disconnect+close; onConnectFailed
onConnectFailed: drop lastDevice/lastRnd; if the attempt came from the cache, set IDLE and connect(null)
                 (re-scan); else fail

GATT callbacks:
  CONNECTED     -> state CONNECTED; requestMtu(247)
  onMtuChanged  -> maxChunk = max(mtu-3, 20); discoverServices()
  onServicesDiscovered -> resolve the 4 chars (ch1 write + notify required); launch setup
  setup: clearBond(device)            # wipe any stale bond; bonding is only for calibration
         enable notify ch1 (required), ch2 (optional); each CCCD write waits up to 4000 ms
         abort if gatt changed or state != CONNECTED
         if no credential: stay CONNECTED
         session.establish()  -> SESSION_READY, reset setupRetries and backoff
         on Exception: handshakeFailStreak++; if from cache, drop the cache
                       if streak >= 3: backoffUntil = now + min(30000 << (streak-3), 120000)
                       fail("DK handshake: …")
  DISCONNECTED  -> abortSetup; session.reset(); clear chars and reassemblers; gatt.close(); gatt=null
       wasReady              -> IDLE (keep-alive decides)
       was CONNECTING & !deliberate -> onConnectFailed
       !deliberate && lastDevice && setupRetries < 3 -> after 900 ms, reconnectLast()   (status-19 drops)
       else fail("disconnected (status=…)")
```
`disconnect()` sets `deliberate=true`, stops the scan, aborts setup, calls `session.reset()` (NOT
`close()`, which would unwire the inbound handler of the reused session), closes the GATT and
returns to IDLE.

`refreshSession(timeout=15000)`: disconnect, wait 800 ms, `reconnectLast() || connect(null)`, then
poll every 200 ms for SESSION_READY. This is the programmatic "BT off/on" used to recover a stale
session.

Bluetooth adapter receiver: on TURNING_OFF/OFF, call `disconnect()` once and
`disarmPresenceScan()`. On ON, flip `adapterEnabled`.

`pollRemoteRssi()`: starts `readRemoteRssi()` and returns the **previous** callback's value. It
returns null when BT is off, there is no GATT, the read cannot start, or the previous read never
called back. A null therefore means the link is wedged.

The BLE manager uses an attribution context with tag `"proximity"` on API 30+.

### 2.6 Writes

`write(cmd, frame)` runs under a mutex. Channel = ch2 if `isChannel2(cmd)`, else ch1. The frame is
split with `DkFragmenter.split(frame, maxChunk)`. Each chunk is written with `WRITE_TYPE_DEFAULT`
(with response), and the next chunk waits up to 4000 ms for `onCharacteristicWrite` success.
Notifications are reassembled per channel (two `DkReassembler`s) and CRC-checked with
`DkFrame.decode`. Then `lastInboundMs` and `onInboundActivity` are updated and the frame goes to the
session.

### 2.7 Positioning beacon (phone advertises)

From session-up until reset/close: legacy `startAdvertising`, ADVERTISE_MODE_LOW_LATENCY, TX_POWER_HIGH,
connectable, timeout 0. Data = manufacturer id **0x7F99**, bytes **`07 09 43 58`**. No name, no
tx power, empty scan response. This is a fixed constant (stock `genPSBroadcast("null")` =
`99 7f 07 09 43 58`). The car's interior anchors need it to localise the phone; without it,
self-cal position 4 returns errCode 8.

### 2.8 Bonding

The handshake is application-layer and needs no bond. Every connect calls `clearBond()`
(`cancelBondProcess` + `removeBond` by reflection) to stop repeated pairing prompts, since the RPA
rotates and an old bond never matches. `ensureBonded()` is used **only for calibration**:
reflective `createBond(TRANSPORT_LE=2)` then wait up to 12000 ms for BOND_BONDED. A timeout is not
fatal, because the car sends 0x0138 on the attempt. `removeBond()` runs after calibration.

---

## 3. Framing and fragmentation

### 3.1 DK frame

```
off  len  field
0    1    magic      0xFE
1    1    version    0x03 (Zeekr)
2    2    len        TOTAL frame length incl. header and CRC (BE)
4    2    cmdId      (BE)
6    1    instType   0 INVALID,1 REQ,2 RSP,3 CON,4 ACK,5 NON,6 CMD
7    n    body       plaintext, or AES-128-GCM ciphertext‖tag(16)
7+n  2    CRC-16/ARC over bytes [0 : len-2]  (BE)
```
HEADER_LEN=7, CRC_LEN=2. CRC-16/ARC: reflected poly 0xA001, init 0x0000, no xorout. Decode
rejects: size < 9, magic != 0xFE, `len != buf.size`, CRC mismatch. The version byte is **not
checked** on decode.

### 3.2 Payload (inside body; inside GCM for encrypted frames)

`nSeq(2) ‖ ts(4) ‖ tail`. `ts` = unix seconds (int32). `nSeq` is a process-global AtomicInteger,
reset to 0 at each `establish()`. `nextSeq` returns 1, 2, … 0x7FFF, then wraps to 1. Every
outbound frame (handshake, control, ACK of our own) takes a new nSeq. The ACK frame instead echoes
the acked frame's nSeq+ts (§5.4).

### 3.3 Outbound instType (`instTypeFor`)

- 0x0113, 0x0116 (RPA, CMAC frames): `INST_CON` (3)
- 0x0192 CALIBRATION_LOC_SEND: `INST_CON`
- 0xFFFE ACK: `INST_ACK` (4)
- everything else: `INST_REQ` (1)

### 3.4 GATT fragmentation

Sender (`DkFragmenter.split(frame, maxChunk)`, `maxChunk = MTU-3`, minimum 20, MTU requested 247
so typically 244):
- `frame.size <= maxChunk`: one chunk.
- otherwise chunk 0 = `frame[0:maxChunk]` verbatim (starts with `FE 03`). Each continuation is
  `fragIdx(2 BE) ‖ totalFrags(2 BE) ‖ next (maxChunk-4) bytes`, with `fragIdx` starting at **1**
  and `totalFrags = ceil((frame.size - maxChunk) / (maxChunk-4))`. totalFrags counts continuations
  only.

Receiver (`DkReassembler`, one per notify channel):
- empty buffer: the chunk must start `FE 03`, otherwise it is dropped. `expected = len` field.
- non-empty buffer: strip the first 4 bytes (fragIdx/total, not validated) and append.
- once `buf.size >= expected`, emit `buf[0:expected]` and reset.
- Caveat: a stray continuation after a reset is dropped silently. There is no timeout or
  index check, so a lost chunk corrupts the next frame until a CRC failure. The author says this
  still needs a btsnoop confirmation.

Application-level chunking for 0x0171 BIG calibration uses `BIG_CALIB_APP_CHUNK = 220` (stock uses
MTU-19). This is defined but not wired in the code read.

### 3.5 Which cmdIds are GCM (`isEncrypted`)

GCM: 0x010B, 0x010C, 0x0110, 0x0111, 0x0112, 0x0113, 0x0116, 0x0120, 0x0121, 0x0151, 0x0152,
0x0159, 0x0190, 0x0191, 0x0192, 0x0193, 0x0196, 0x0197, 0x0195, 0x0199, 0x0137, 0x0138.
Also **0x0182** (car ranging push, not in the table but decrypted explicitly).

Plaintext: 0x0101/0x0102 (CBC under connectKey, see §4), 0x0103–0x0108, 0x0109/0x010A,
0x0114, 0x0115, 0x0117, 0x0118 (car→phone RPA telemetry is PLAINTEXT, verified at the car),
0x0158 RSSI_SYNC, 0x0171–0x0173, 0x0194, 0x0198, 0xFFFE ACK.

### 3.6 Which cmdIds ride channel 2 (`isChannel2`)

0x0172, 0x0173, 0x0151, 0x0152, 0x0190, 0x0192, 0x0196, 0x0195, 0x0198, 0x0199. Everything else,
including 0x0171 BIG calib and 0x0110 control, uses channel 1. Inbound is accepted on either.

---

## 4. Handshake (`RealDkSession.establish`)

Primitives: P-256 ECDH (full point X‖Y via BouncyCastle), ECDSA-SHA256 (DER), AES-128-CBC/PKCS7,
AES-128-GCM (tag 128 bit, **AAD = IV**), SHA-256. The default response timeout is `timeoutMs = 8000`
per step.

### 4.0 Pairing epoch: 0x0101 CONNECT_CONFIRM, then 0x0102 DK_STATUS

```
rnd = broadcastRnd (8 bytes, from the advert, §2.2). Required, so you cannot connect by MAC.
connectKey[i] = ascii(VIN)[i] XOR asciiHexUpper(rnd)[i]  for i = 0..15
      # asciiHexUpper(rnd) = 16 ASCII chars "0123456789ABCDEF" of the 8 rnd bytes
CBC_IV = 1d 0a 5d ba 3c a5 d8 07 53 1d 61 22 a6 6c 26 17     (fixed, from CipherEngine.cbcIv)

d   = SHA256(rnd); idx = d[0] & 0x0F; sha8 = d[idx : idx+8]
confirm (43 bytes) = nSeq(2) ‖ ts(4) ‖ initState(1)=0x00 ‖ dkID(4)=hex(bookId) ‖ sha8(8)
                   ‖ phoneId(8)=deviceId[0:8] ‖ phoneType(3)=mobileCode ‖ bigCalibHash(4)
                   ‖ smallCalibHash(4) ‖ selfCalibHash(4)=00000000 ‖ calibType(1)=0x00
body = AES-128-CBC-PKCS7(connectKey, CBC_IV, confirm)            # 48 bytes
send frame cmd 0x0101, instType REQ, plaintext body (not GCM) on ch1; await 0x0102
status = AES-CBC-decrypt(connectKey, CBC_IV, 0x0102 body)        # failure = wrong VIN/rnd
errCode = status[6..7] (BE u16)      # bytes right after nSeq‖ts
```
initState is always 0 on the wire (stock `isInitState()` is hard-coded to 0).

Retry loop:
- errCode `0x100C` EEC_busy ("BNCM busy"): wait 2500 ms and re-send, up to 6 times. This matches
  stock "EEC_busy Wait 2.5s ReStart".
- No 0x0102 (timeout): wait 1200 ms and re-send, up to 3 re-sends. CancellationException and
  DkLinkDropped are rethrown immediately.

Branch on errCode:
- `0x1011` EEC_notAuthenticated: **first pair**, continue with the cert exchange.
- `0x1012` EEC_authenticated: already paired, so stock skips the cert step and goes straight to the
  factor exchange. **NOT IMPLEMENTED**: the code throws "reconnect flow not implemented". In
  practice every connect gets 0x1011 and does the full first-pair handshake.
- `0x1010` EEC_confirmFailed: terminal. The vehicle has no registration for (dkId, deviceId)
  because the cloud-to-car push has not landed. Wake the car and retry.
- anything else: terminal "unexpected".

### 4.1 Cert exchange: 0x0103, then 0x0104

```
send 0x0103 body = nSeq‖ts‖ourLeafCertDER   (plaintext)
await 0x0104; carCertDER = body[6:]
early failure: if the car sends 0x0105 APP_CERT_VERIFY_FAILED, the 0x0104 wait fails immediately
```
### 4.2 Vehicle trust check (`DkTrust`), before any key material is released

```
requireGeelyVehicleCert(carCert):
   trust store not empty (fail closed); carCert.checkValidity();
   carCert.verify(ca.publicKey) must succeed for at least one baked CA
if pin store present:
   fp = lowercase hex SHA256(carCert.encoded)
   if pins[vin] exists and != fp (case-insensitive): FAIL "vehicle cert changed … fake/relay car"
   (do NOT write the pin yet: the cert is cleartext and replayable)
```
Baked CAs are 6 public Geely Trust Center PROD certs: Root CA, Global policy Prod CA,
ECU Issuing CN-CA, ECU Issuing EU-CA, ZK ECU Issuing CN-CA, ZK ECU Issuing EU-CA. Copy the PEMs
verbatim from `DkTrust.kt`. The check is a direct signature verify against any CA in the list. It
does not build a chain, so a leaf must be signed directly by one of these.

### 4.3 Factor exchange: 0x0106, then 0x0108

```
eph = new P-256 keypair (per session)
factor = X(32) ‖ Y(32) of eph.pub                 # no 0x04 prefix
content = nSeq(2) ‖ ts(4) ‖ factor                # 70 bytes
body = content ‖ SHA256(content)(32) ‖ ECDSA_SHA256_DER(longTermPriv, content)
send 0x0106 plaintext; await 0x0108 (0x0107 PARSE_APP_FACTOR_FAILED fails it early)
vf = 0x0108 body; require len >= 102
vContent = vf[0:70]; carFactor = vf[6:70]; digest = vf[70:102]; sig = vf[102:]
check SHA256(vContent) == digest
check ECDSA verify(carCert.publicKey, vContent, sig)
shared = ECDH_point(eph.priv, 04‖carFactor) = X(32)‖Y(32)
sKey = X[0:16]            # AES-128-GCM key
iv   = Y[0:12]            # = shared[32:44], STATIC IV for the whole session
```
After the factor signature verifies, the car has proven it holds the cert key, so
`commitPin(fp)` writes the pin if none exists (re-checking if one does). `cryptoReady = true`.

### 4.4 GCM rule (critical)

`ciphertext‖tag = AES-128-GCM(key=sKey, iv=iv(12), aad=iv(12), plaintext=nSeq‖ts‖tail)`, tag 16 bytes.
**AAD must equal the IV.** Without it the car rejects with EEC_skeyErr 0x1031. The IV is static, so
nonce uniqueness rests entirely on nSeq/ts changing inside the plaintext. Cryptographically that is
weak, but it is what the car does. There is no per-frame counter in the IV. Inbound GCM uses the
same key and IV.

### 4.5 Register key: 0x010B, then 0x010C

`send 0x010B GCM(nSeq‖ts‖digitalKey)`; await 0x010C. Failure is only **logged** (runCatching). The
0x010C payload is not parsed.

### 4.6 Coef upload: 0x0172, then 0x0173 (ch2, plaintext)

`send 0x0172 nSeq‖ts‖coefSmall`; await 0x0173. Failure is logged only. 0x0171 BIG calib is never sent.

Then: `isEstablished = true`, `establishedAtMs = lastVerifiedMs = now`, and the positioning beacon
starts (§2.7).

Removed and intentionally not sent: the 0x0137 PAIRING_REQ replay (it came from a misread Frida hook).

### 4.7 Pseudocode summary

```
establish():
  resetSeq(); rnd=advert.rnd; ck=VIN16 ^ HEX(rnd)
  loop: err = CBCdec(ck, exchange(0x0101, CBCenc(ck, confirm43)))[6:8]   (busy/stall retries)
  require err==0x1011
  carCert = exchange(0x0103, myCert)->0x0104 ; trustCheck(carCert); pinCheck
  eph=gen(); c=seq‖ts‖XY(eph); vf = exchange(0x0106, c‖sha(c)‖sign(c))->0x0108
  verify(vf, carCert); (X,Y)=ECDH(eph, vf[6:70]); K=X[0:16]; IV=Y[0:12]; commitPin
  try exchangeGCM(0x010B, digitalKey)->0x010C
  try exchange(0x0172 ch2, coefSmall)->0x0173
  ready; startBeacon()
```

### 4.8 Session reset

`reset()`: isEstablished=false, cryptoReady=false, cmacKeyCache=null, timestamps=0, stop beacon,
complete every pending waiter exceptionally with `DkLinkDropped`. This is a plain Exception, not a
CancellationException, so it never surfaces as the obfuscated "w0 was cancelled" (issue #3).
`close()` = reset + `transport.close()`, which nulls the inbound handler. Use `reset()` on drops.

---

## 5. Opcode catalog

### 5.1 cmdIds

| cmdId | dir | name | enc | ch | payload tail (after nSeq‖ts) / notes |
|---|---|---|---|---|---|
| 0x0101 | A→V | CONNECT_CONFIRM | CBC | 1 | 43-byte confirm (§4.0) |
| 0x0102 | V→A | DK_STATUS | CBC | 1 | errCode u16 at [6:8] |
| 0x0103 | A→V | SEND_APP_CERT | plain | 1 | leaf cert DER |
| 0x0104 | V→A | SEND_VEHICLE_CERT | plain | 1 | vehicle cert DER |
| 0x0105 | V→A | APP_CERT_VERIFY_FAILED | plain | 1 | fails 0x0104 wait. Cause: car has no deviceId binding (needs repush/share-key) |
| 0x0106 | A→V | SEND_APP_FACTOR | plain | 1 | factor‖sha256‖sig (the payload includes its own nSeq‖ts) |
| 0x0107 | V→A | PARSE_APP_FACTOR_FAILED | plain | 1 | fails 0x0108 wait |
| 0x0108 | V→A | SEND_VEHICLE_FACTOR | plain | 1 | same layout |
| 0x0109/0x010A | | DK_PRE_SYNC / RESP | plain | | unused |
| 0x010B | A→V | SEND_DKEY | GCM | 1 | digitalKey |
| 0x010C | V→A | DK_VERIFY_STATUS | GCM | 1 | not parsed |
| 0x0110 | A→V | CONTROL | GCM | 1 | 1 byte ctrl (§5.2) |
| 0x0111 | V→A | CMD_RECEIVED | GCM | 1 | receipt. Echoes nSeq; tail carries a receipt code (e.g. 0x1040 cmdNotSupport for ctrl 0x0A) |
| 0x0112 | V→A | RESULT | GCM | 1 | errCode u16 at body[6:8]; non-zero = rejected |
| 0x0113 | A→V | RPA_REQ | GCM+CMAC | 1 | `rpaControl, rspaControl, outMode, phoneStatus` ‖ CMAC6. instType CON |
| 0x0114 | V→A | RPA_STATUS | plain | 1 | status byte at tail[0] |
| 0x0115 | V→A | RPA_CHALLENGE | plain | 1 | randX, randY, authStatus, … |
| 0x0116 | A→V | RPA_ANSWER | GCM+CMAC | 1 | `phoneStatus, randX, randY, ansHi, ansLo, gesture` ‖ CMAC6. CON |
| 0x0117 | V→A | RPA_SYNC | plain | 1 | 500 ms stream during RPA; contains prkgModIncln (offsets unknown) |
| 0x0118 | V→A | RPA_SYNC2 | plain | 1 | status byte at tail[0] |
| 0x0120 | A→V | TRANS | GCM | 1 | unused |
| 0x0121 | V→A | VSTATUS_SYNC | GCM | 1 | vehicle status push on state change. **Must be ACKed** |
| 0x0137 | A→V | PAIRING_REQ | GCM | | not sent |
| 0x0138 | V→A | PAIRING_RESP | GCM | | sent only on a bonded link before calibration. ACKed |
| 0x0151 | A→V | CUST_REQ | GCM | **2** | `type(1), data(1)`: type 0x01 APPROACH_UNLOCK, 0x02 WALK_AWAY_LOCK; data 1=on, 0=off. The only wire form (no cloud path) |
| 0x0152 | V→A | CUST_RESP | GCM | 2 | ignored (fire-and-forget) |
| 0x0158 | A→V | RSSI_SYNC | plain | 1 | int32 BE dBm (RPA proximity gate) |
| 0x0159 | V→A | APPROACHLOCK_NOTIFY | GCM | 1 | not handled |
| 0x0171 | A→V | BIG_CALIBRATION_DATA | plain | 1 | fragmented `pakegeSum(2) pakegeIndex(2) slice`; not sent |
| 0x0172 | A→V | SMALL_CALIBRATION_DATA | plain | 2 | coefSmall |
| 0x0173 | V→A | SMALL_CALIB_RESP | plain | 2 | |
| 0x0182 | V→A | RANGING_KEEPALIVE | GCM | ? | BNCM ranging telemetry every 2–5 s; decrypted for logs/liveness only, no reply |
| 0x0190 | A→V | CALIBRATION_START | GCM | 2 | `type(1)` → 0x0191 |
| 0x0191 | V→A | CALIBRATION_RSP | GCM | | errCode = body[6] |
| 0x0192 | A→V | CALIBRATION_LOC_SEND | GCM | 2 | `type/step(1)`, instType CON → 0x0193 (car samples about 8–10 s) |
| 0x0193 | V→A | CALIBRATION_LOC_RSP | GCM | | errCode = body[6]. **ACK** |
| 0x0194 | V→A | RECEIVE_CALIBRATION | plain | | `calib(200) ‖ hash(4)` at body[6:206], [206:210]; short variant body[6:22]. **ACK** |
| 0x0195 | A→V | SEND_CALIBRATION | GCM | 2 | non-Zeekr, unused |
| 0x0196 | A→V | PE_MODE_REQ | GCM | 2 | `mode(1)` → 0x0197 errCode |
| 0x0198 | A→V | SELF_CALIBRATION_DATA | plain | 2 | 200-byte stored table, no response |
| 0x0199 | A→V | CALIBRATION_MODEL_ZEEKR | GCM | 2 | `model(1)`, no response |
| 0xFFFE | A→V | ACK | plain | 1 | §5.4 |

### 5.2 0x0110 control sub-opcodes (VehicleCtrlCmd, byte = enum ordinal - 1)

`00 NULL, 01 UNLOCK, 02 LOCK, 03 CAR_LOCATOR, 04 HOOD_UNLOCK, 05 PANIC_SEARCH, 06 TRUNK_UNLOCK,
07 TRUNK_LOCK, 08 ENGINE_REMOTE_START, 09 KEY_INSIDE, 0A RPA_START, 0B KEY_OUTSIDE, 0C WINDOW_UP,
0D WINDOW_DOWN, 12 VENTILATION, 13 CHARGE_LID, FF UNDEFINED`. Only 01/02 are used for actuation.
**0x0A is the liveness ping**: the car replies 0x0111 with receipt 0x1040 and never actuates.
(The task brief's "0x110 lock / 0x111 unlock" is wrong: 0x0110 is the CONTROL frame, sub-byte 02
is lock and 01 is unlock, and 0x0111 is the car's receipt.)

### 5.3 Status / error codes (u16)

| code | meaning |
|---|---|
| 0x1000 | OK (ACK status) |
| 0x100A | EEC_cmdMatchErr: NAK, e.g. RPA REQ_MODE while RPA is not armed on the head unit, or answering a dummy challenge |
| 0x100C | EEC_busy (BNCM busy): retry after 2.5 s |
| 0x1010 | EEC_confirmFailed: car has no registration for the key (cloud push missing, or dkStatus advanced to 5) |
| 0x1011 | EEC_notAuthenticated: first pair |
| 0x1012 | EEC_authenticated: reconnect (not implemented) |
| 0x1031 | EEC_skeyErr: GCM/session-key error (e.g. AAD missing) |
| 0x1040 | cmdNotSupport (receipt for ctrl 0x0A) |
| errCode 8 on 0x0193 | self-cal position 4 failed (interior anchors cannot see the phone / no beacon) |

### 5.4 Transport ACK (0xFFFE)

Sent fire-and-forget on ch1, plaintext, instType ACK, for inbound **0x0121, 0x0193, 0x0194, 0x0138**
(only when cryptoReady). It is sent before the pending-waiter completion.
`body = ackedFrame.nSeq(2) ‖ ackedFrame.ts(4)` (echoed from the decrypted acked frame, not a fresh
seq) `‖ ackedCmdId(2) ‖ 0x10 0x00`.
Example: `fe 03 | 00 13 | ff fe | 04 | 0001 6ab3d534 0193 1000 | crc16` (19 bytes total).
Without the ACK the car stalls (for example it never sends the 0x0194 table).

### 5.5 Session API semantics

- `control(ctrl, timeout)`: one mutex (`controlExchange`) shared with ping. Register waiters for
  0x0111 and 0x0112, send 0x0110. No 0x0111 within timeout gives NO_RESPONSE. Then wait up to
  `RESULT_WINDOW_MS = 600` for 0x0112: errCode != 0 gives REJECTED, otherwise CONFIRMED. A missing
  0x0112 also counts as CONFIRMED (successful unlocks send only 0x0111). A write failure gives
  WRITE_FAILED. Success updates `lastVerifiedMs`.
- `ping(timeout)`: sends 0x0110/0x0A and is true only if a 0x0111 that **decrypted under this
  session key** arrives. Other pushes do not count.
- `probeControl(ctrl, window)`: debug. Sends 0x0110 with any byte and collects every decrypted
  inbound frame for `window` ms.
- Inbound dispatch (`onRawInbound`): GCM-decrypt if `cryptoReady && isEncrypted(cmd)`; drop on
  failure. Special-case 0x0182 (try decrypt and set lastAuth182Ms). ACK rule (§5.4). Latch 0x0194.
  Complete `pending[cmd]` if present. 0x0105 fails pending 0x0104; 0x0107 fails pending 0x0108.
  Otherwise call `appHandler(cmd, body[6:])`. There is a single app handler, and the RpaController
  owns it.
- `DkLockController.unlock/lock`: `ensureSession()` (establish on the live GATT, else
  `refresh()` = `DkBleManager.refreshSession`), then `control(ctrl, ACK_TIMEOUT_MS=3000)`.
  CONFIRMED gives true. REJECTED gives false with no retry. NO_RESPONSE or WRITE_FAILED triggers one
  refresh and one retry.
- `sendCustomCommand(type, enable)`: 0x0151 on ch2, fire-and-forget.

---

## 6. Session lifecycle

### 6.1 Ownership model

- `DkBleManager` is a process singleton holding **one** `RealDkSession` instance, which is reused
  across reconnects. The inbound handler is wired once in `init`, which is why `reset()` is used
  rather than `close()`.
- **`ProximityService` (foreground service) is the sole owner of the connection** (the
  keep-alive). `ProximityController` only reads RSSI and sends controls. In its lock/unlock loops it
  also calls `disconnect`, `reconnectLast` and `connect`, so in practice it does touch the link (§10).
- The car accepts **one BLE peer** at a time. Phone and watch hold clones of the same identity, so
  they must take turns (§6.4).

### 6.2 Foreground service (`ProximityService`)

- `startForeground`. FGS type `CONNECTED_DEVICE` (API 30+). Channel id `"proximity"`
  (IMPORTANCE_LOW). Notification id `42`, ongoing, `FOREGROUND_SERVICE_IMMEDIATE`. `START_STICKY`.
  Started once the user is logged in and provisioned.
- Intents: `ACTION_PRESENT = com.openzeekr.app.ble.PROX_PRESENT` (extra `"mac"`) calls
  `ble.engageFromPresence(mac)`. `ACTION_ABSENT = com.openzeekr.app.ble.PROX_ABSENT` is a no-op
  (carInRange has already been cleared).
- Launched coroutines: `keepConnected`, `runApproach`, `presenceByWalking`, `sigMotionBaseline`,
  collectors (significantMotion opens a sig window with lowLatency; walkAwayLocked opens one without;
  demandScanMiss opens one with lowLatency), `manageWakeLock`, and `pollCarMessages` (inbox, 5 min,
  outside this scope).
- Sets `ble.passiveListening = true`. onDestroy clears it, stops proximity, disarms presence,
  unregisters receivers and releases the wakelock.

**`autoProximityWanted`** = `proximityEnabled && isProximityCalibrated && (autoUnlockOnApproach || autoLockOnWalkAway)`.
When false: no presence scan and no keep-alive (zero battery). Manual lock/unlock then connects on demand.

**`keepConnected`** loop, every `RECONNECT_INTERVAL_MS = 8000`:
```
if WearLinkArbiter.linkSuspended:
    if expired (45 s): resume()
    else: if state not IDLE/ERROR: ble.disconnect();  delay 1000; continue
if !autoProximityWanted: disarm presence; wantedPresenceMode=null; continue
if hasCredential && BT on:
   offload = presenceOffloadEnabled (default true)
   SIGMOTION source && wanted==null -> wanted = BACKGROUND
   if state IDLE/ERROR:
       !offload            -> connect(null)               # legacy continuous scan-connect
       first idle tick     -> connect(null) once ("already at the car" probe; FIRST_MATCH is edge-only)
       MOVING && carInRange-> connect(null)               # aggressive reconnect while walking in range
       ensurePresenceArmed()
   else ensurePresenceArmed()
```
No proactive link cycling. A stale session is caught by the controller's liveness check.

**`manageWakeLock`**: hold a PARTIAL_WAKE_LOCK `openzeekr:dk-keepalive` (no timeout) while
`state in {SCANNING, CONNECTING, CONNECTED}` OR `proximity.wakeLockNeeded` OR `sigMotionActive`.
Release otherwise. The value is passed through distinctUntilChanged.

**`runApproach`**: start or stop `ProximityController` to follow `autoProximityWanted`.

### 6.3 Reconnection summary

| trigger | action |
|---|---|
| status-19 drop mid-setup | `reconnectLast` after 900 ms, up to 3 times |
| connect never reached CONNECTED (timeout 12 s / 133 / 147) | drop cache; re-scan if the attempt came from the cache, else ERROR |
| handshake failure | streak counter; from 3 failures, back off 30 s, 60 s, 120 s max (auto connects only; user connects call `resetHandshakeBackoff`) |
| READY link drops | IDLE; keep-alive and proximity decide |
| RSSI read null 5 times in a row on READY | `forceReconnect` (disconnect, wait for IDLE/ERROR ≤1500 ms, then `reconnectLast() || connect(null)`) |
| liveness verify fails (§7.6) | `forceReconnect` |
| lock/unlock NO_RESPONSE | `refreshSession` (DkLockController) or `resetLink` (proximity loops) |
| BT adapter OFF | disconnect + disarm. ON: keep-alive reconnects |
| cached device older than 10 min | scan instead of reconnectLast |

There is **no keep-alive ping on a timer**. Liveness is verified only when an unlock may be coming
(§7.6). The car pushes 0x0182 every 2–5 s and 0x0121 on state changes, which the code logs as
candidate passive liveness signals but does not act on. Per the README, the car seems to time out
its session epoch after a while, leaving the GATT up but commands ignored. That is why there are
refresh-and-retry paths everywhere.

### 6.4 Phone/watch single-slot arbitration (pause, act, resume)

Phone state: `WearLinkArbiter` { `linkSuspended: StateFlow<Boolean>`, `suspendedAtMs` },
`AUTO_RESUME_MS = 45000`.

Watch `act(lock)`:
```
s = PhoneLink.queryStatus()                    # 3 s timeout; no reply means ABSENT
if s.present && s.prox && s.connected: stand down (do nothing; the phone owns it)
elif !s.present: connectAndRun()               # standalone watch
else:
   if !pauseAndAwait() (6 s): fail "Phone didn't hand over"
   r = connectAndRun(); ble.disconnect(); PhoneLink.resume(); return r
connectAndRun: if !READY: resetHandshakeBackoff(); connect(null); wait ≤25 s for READY|ERROR
               then DkLockController.lock()/unlock()  (3 s ack, one refresh-retry)
```
Phone on PAUSE: `suspendForWatch()`; `ble.disconnect()`; wait up to 3000 ms for IDLE/ERROR; wait
`CAR_SLOT_SETTLE_MS = 1000`; send PAUSED. While suspended, keep-alive disconnects every 1 s if needed.
On RESUME (or after 45 s): `resume()`, and keep-alive reconnects on its next tick.
The watch UI polls status + snapshot every 4000 ms while resumed and not busy.

---

## 7. Proximity algorithm (`ProximityController`)

### 7.1 Inputs and config

- RSSI comes **only from the connected GATT**: `pollRemoteRssi()`, which returns the previous
  read's result. There is no advert-RSSI ranging, and no car 0x0182 ranging is used.
- Config (`SecretsConfig`):
  `proximityEnabled=false` (master), `autoUnlockOnApproach=true`, `autoLockOnWalkAway=true`,
  `proximitySensitivity="close"`, `lockSensitivity="close"`, `calibNearRssi/calibFarRssi/calibInsideRssi=0`,
  `presenceOffloadEnabled=true`, `proximityExclusionZones=[]` (GeoZone, default radius 150 m).
  Legacy or unused: `unlockRssi=-65`, `lockRssi=-70`, `proximityLostMs=8000`, `proximityDeviceMac=""`,
  `CONNECT_RSSI_FAR=-90`, `UNLOCK_RSSI_FLOOR=-65`.
- `isProximityCalibrated` = `near<0 && far<0 && near-far >= CALIB_MIN_SPAN_DB(4)`. **Proximity
  will not start without a calibration.**

**Thresholds** (`LOCK_RSSI_GAP_DB = 10`):

| | uncalibrated | calibrated (span = near − far > 0) |
|---|---|---|
| unlock "veryclose" | −58 | near − 3 |
| unlock "close" | −66 | near − round(0.50·span) |
| unlock "far" | −74 | far + round(0.30·span) |
| lock "veryclose" | −72 | far + round(0.20·span) |
| lock "close" | −76 | far |
| lock "far" | −84 | far − round(0.50·span) |

`lockThresh = min(preset, unlockThresh − 10)`, so lock is always at least 10 dB weaker than unlock.

Distance (display and the NEAR/FAR cadence machine only): `d = 10^((−59 − rssi)/(10·2.5))`. NEAR means
`d < 6.0 m`, which is smoothed RSSI above about −78.5 dBm.

### 7.2 Smoothing

```
delta = rssi − ema_prev;  jumping = |delta| >= 4 dB
alpha = (nextInterval <= 200ms || jumping) ? 0.6 : 0.35
ema = ema_prev + alpha·(rssi − ema_prev)   (the first sample seeds it); smoothed = (int) ema
trend = ema − ema_prev; receding = trend < −0.6   (stored only; no longer gates decisions)
zone = smoothed >= unlockThresh ? NEAR : smoothed <= lockThresh ? FAR : previous zone (hysteresis)
```
The EMA resets on link loss, on resuming after RPA, and on start.

### 7.3 Monitor loop (per tick)

```
if rpaBusy: wakeLockNeeded=true; delay 800; continue            # stand down fully during RPA
linkUp = state in {SESSION_READY, CONNECTED}; if linkUp: sessionWasUp = true
freshDrop = !linkUp && sessionWasUp && linkLostAtMs==0
if !freshDrop && stillIdle(): idleUntilWalking(linkUp); continue
   stillIdle = motion.hasSource && motion != MOVING && !walkAwayArmed && no lock/unlock job active
   idleUntilWalking: wakeLockNeeded=false; block until onMovingEdge, link drop, or 10 min
if linkUp:
   clear link-loss state
   if armedUnlocked: wakeLockNeeded=true; armedWatch(); continue
   rssi = pollRemoteRssi(); null -> streak++, and at 5 on READY: forceReconnect; else onSample(rssi)
else onSessionDown()
if farAsleep: sleepUntilMotion() (≤60 s, then wakeLockNeeded=true) else delay(nextIntervalMs)
```

**Cadence (`onSample`)**:
- NEAR (d<6 m): wakelock held. 200 ms, then 500 ms after holding still (±0.5 m) for 30 s, then
  1000 ms after 60 s.
- FAR with no motion source: wakelock held. `clamp(d/1.4 m/s, 2000, 30000)`, or 30000 once RSSI has
  been steady (±4 dB) for 12 s.
- FAR while MOVING: wakelock held. `clamp(d/1.4·1000, 2000, 3000)` ms.
- FAR and motion UNKNOWN/STILL: release the wakelock, `farAsleep=true` (sleep until motion).
- No session (`onSessionDown`): 800 ms. Wakelock held only if `walkAwayArmed` or (MOVING and in the
  presence window, i.e. `!offload || carInRange`).

### 7.4 Decisions (in `onSample`, after cadence)

Gates: skip if within `ACTION_COOLDOWN_MS = 5000` of the last trigger, or an action is in flight,
or `state != SESSION_READY`.

1. **Approach-unlock**: `autoUnlockOnApproach && !armedUnlocked && !needToUnlock && smoothed >= unlockThresh
   && (prevZone != NEAR || !arrivalActed)`. Sets `arrivalActed=needToUnlock=true` and starts
   `startUnlockLoop()`. The `arrivalActed` clause makes "connected while already at the car" fire
   once.
2. Otherwise, if (NEAR or MOVING) and not armed: `ensureVerified()` (§7.6).
3. `smoothed <= lockThresh` clears `arrivalActed` and starts the lock dwell timer
   (`lockBelowSinceMs`). Going above resets the dwell.
4. If an unlock is pending and `smoothed <= lockThresh`, cancel the unlock loop.
5. **Walk-away lock (connected)**: `armedUnlocked && smoothed <= lockThresh` held for
   `LOCK_DWELL_MS = 5000`. Then `armedUnlocked=false`; if not in an exclusion zone, call
   `startLockLoop("walk-away-lock")` and emit `walkAwayLocked`.

**Unlock loop**: skipped in an exclusion zone. Up to `MAX_UNLOCK_ATTEMPTS = 5`: wait ≤8000 ms for
READY (else `resetLink`); `control(UNLOCK, 1500)`. CONFIRMED sets `armedUnlocked=true`, clears the
Sentry latch, and starts the cooldown. Any other result runs `resetLink()` (disconnect, wait ≤1500
for IDLE, `reconnectLast||connect`, wait ≤15000 for READY) then waits 400 ms.

**Lock loop** (all lock paths go through it). Gated by `autoLockOnWalkAway` and the exclusion zone.
Up to `MAX_LOCK_ATTEMPTS = 5`: wait ≤3000 ms for READY (else `reconnectLast||connect`);
`control(LOCK, 1500)`; on failure `resetLink`, then 400 ms. If never confirmed, **cloud lock fallback**.
Then `verifyLockThenArm`.

**verifyLockThenArm**: cloud status read (`centralLockingStatus=="1"`, open parts = driver,
passenger, rear doors, boot, bonnet). Locked or unknown: fire `onWalkAwayLocked` (Sentry auto-arm,
de-duplicated per locked episode). Not locked: **relock watch** for `RELOCK_WATCH_MS = 300000`,
polling every `RELOCK_POLL_MS = 25000` under wakelock `openzeekr:relock-watch` (315 s). When nothing
is open, re-lock (BLE if READY, else cloud). Notifications on the SECURITY channel: "Car not locked",
"Car locked", "Car still not locked … Gave up after 5 min".

### 7.5 Link loss

`onSessionDown` (first tick after the drop): `linkLostAtMs=now`; `walkAwayArmed = armedUnlocked`.
- If **not** armed (we did not unlock it): run `cloudLockSafetyNet` once per loss. It holds wakelock
  `openzeekr:cloud-oor-lock` (20 s), waits `LINK_LOSS_LOCK_DELAY_MS = 5000`, and skips if READY
  again or inside an exclusion zone. Then `cloudIsLocked()`: true means fire the Sentry hook and stop;
  false or unknown means cloud lock and verify. Gated by `autoLockOnWalkAway`. **Note**: this locks
  the car through the cloud on any sustained drop, even one the app did not unlock.
- If armed, and the link has stayed down ≥5000 ms: `startLockLoop("walk-away-lock (link down)")`,
  which reconnects up to 5 times and then falls back to the cloud.

**Armed watch** (unlocked by us, link up; replaces polling). If no inbound frame for ≥
`ARMED_ACTIVE_MS = 4000`, block until the next car frame (`onInboundActivity`) or `ARMED_IDLE_MAX_MS = 3000`.
On that timeout do one RSSI read: `rssi <= lockThresh` gives `startLockLoop("idle-far-lock")`
(with no dwell). A null read never locks. With recent activity, track at full speed: `onSample`
every 200 ms.

### 7.6 Session verification (liveness)

`ensureVerified`: only on READY, with no unlock/lock/action/reconnect/RPA in flight. If
`now − session.lastVerifiedMs >= VERIFY_FRESH_MS (15000)`, ping (0x0110/0x0A, wait for an
authenticated 0x0111) up to `VERIFY_ATTEMPTS = 2` times with `VERIFY_TIMEOUT_MS = 1000`. Both fail
means `forceReconnect()`. `lastVerifiedMs` also updates on any confirmed control.

### 7.7 Motion gating (`MotionMonitor`)

Source tiers, first available wins:
1. `TYPE_MOTION_DETECT` / `TYPE_STATIONARY_DETECT` one-shot triggers (re-armed alternately):
   SENSORS, both edges.
2. Wake-up `TYPE_STEP_DETECTOR` (registered with `SENSOR_DELAY_NORMAL`): STEP. Each step means
   MOVING; no step for `STEP_STILL_TIMEOUT_MS = 5000` means STILL.
3. `TYPE_SIGNIFICANT_MOTION` (one-shot wake-up, re-armed on every trigger) plus any step detector:
   SIGMOTION. A trigger means MOVING, emits `significantMotion`, and arms the 5 s still timeout.
4. Non-wake-up step detector: STEP (works screen-on only).
5. Play-services Activity Recognition ENTER transitions for STILL, WALKING, ON_FOOT, RUNNING,
   IN_VEHICLE, ON_BICYCLE: ACTIVITY. Receiver action `com.openzeekr.app.ACTIVITY_TRANSITION`,
   request code `0x2ee6`, needs ACTIVITY_RECOGNITION. STILL means STILL; anything else means MOVING
   (IN_VEHICLE also sets `inVehicle`).
6. NONE: Motion UNKNOWN, and the controller uses the RSSI-steadiness fallback.
`hasWakeUpSource` = any of motion/stationary is wake-up, or a wake-up step detector exists, or
sig-motion exists. `onMovingEdge` fires on each transition to MOVING.

**Presence-scan driving** (`presenceByWalking`, sources other than SIGMOTION):
- `!autoProximityWanted` or `!offload`: no scan.
- `!hasWakeUpSource`: BACKGROUND scan always on.
- MOVING: WALKING (LOW_LATENCY); after `LONG_WALK_AFTER_MS = 300000`, LONG_WALK (BALANCED).
- STILL for `WALK_END_STILL_MS = 30000` (timed wakelock `openzeekr:walk-end`, 35 s): scan **off**.

**SIGMOTION tier** (no wake-up step detector): BACKGROUND (LOW_POWER) baseline while idle. An
ACTIVE window holds the CPU via `sigMotionActive`. Openers: sig-motion or demand-scan-miss
(WALKING for `SIG_LOWLAT_MS = 300000`, then LONG_WALK), walk-away-lock, or an HFP (car hands-free)
disconnect while unlocked (`BluetoothHeadset.ACTION_CONNECTION_STATE_CHANGED`) (LONG_WALK). The
window closes on continuous STILL for `SIG_STILL_STOP_MS = 30000` or after `SIG_ACTIVE_MAX_MS = 1800000`
(ticks every 2000 ms), then drops back to the BACKGROUND baseline.

### 7.8 Trusted areas (exclusion zones, issue #42)

`isInExclusionZone()`: when `proximityExclusionZones` is empty, false. Otherwise check the phone's
cached location fix first (`sentryAutoArm.phoneZoneStateFast`, offline-safe). If there is no phone
fix, use the car's cloud position when it is non-zero and `posCanBeTrusted != false`. If neither is
available, return **false** (fail toward acting). It suppresses the unlock loop, the lock loop, the
onSample walk-away lock (including the Sentry hook) and the cloud backstop. Sentry exclusion zones
are a separate list and do not affect proximity. Car-side passive entry (0x0151) is not affected by
zones.

### 7.9 Calibration

**A. Phone-side anchors** (what gates proximity), captured during the car self-cal walk
(`CalibrationTestController.runCalibration`). While the car samples each position, the phone polls
`pollRemoteRssi` every 400 ms and takes the median (sorted[n/2]).
near = pos1 (driver door handle, phone back against the door); far = min(pos2 6 m driver side,
pos3 6 m rear); inside = pos4 (wireless charging pad). Saved only if `near − far >= 4`.

**B. Car self-calibration** (0x0190–0x0199), the stock 4-step flow:
```
ensureSession (≤25 s); session.resetCalibTableLatch()
ble.ensureBonded()  (createBond LE, ≤12 s; non-fatal). The car gates 0x0138 + calibration on a bond
0x0199 model=1 (ENTER); delay 400
0x0190 type=1 -> 0x0191 errCode (−1 = no reply, abort)
for pos 1..4: wait for the user "Continue" (≤180 s); 0x0192 type=pos (instType CON) -> 0x0193
              within 15 s (the car samples about 8–10 s; the ACK is mandatory); delay 400
   expected 0x0193 errCode: positions 1-3 OK; pos4 = 7 (finalize with table), 8 = error
persist phone anchors
await 0x0194 (≤30 s; latched in case it arrived early) -> table(200)+hash(4) ->
      files filesDir/selfcalib_table.bin, selfcalib_hash.bin
0x0196 PE mode=1 -> 0x0197; 0x0151 WALK_AWAY_LOCK enable
finally: 0x0190 type=2 (STOP/flush, 2500 ms) ; 0x0199 model=0 (EXIT) ; removeBond()
```
Without the stop/exit bracket the car stays in calibrating state and returns errCode 8 forever.
Without the phone positioning beacon (§2.7), pos4 returns errCode 8.
**Replay** (no walking): 0x0198 table (plaintext, ch2), 200 ms, 0x0199 model=1, 200 ms, 0x0196
mode=1, 200 ms, 0x0151 walk-away enable.
**Car-side passive entry toggles**: 0x0151 type 1 (approach-unlock) or type 2 (walk-away-lock),
data 1/0. The car only acts once a calibration model exists. The car then runs it everywhere,
ignoring app exclusion zones, and support varies by market and firmware. It may be owner-gated.
The current state can be read from key-list `approachUnlock`/`walkAwayLock` (§1.5).

Status: per the code comments the finalize at position 4 has historically failed (errCode 8, the
"position-4 finalize" issue), with phoneType and coef suspected. The CHANGELOG (0.1.8) says self-cal
now completes under openzeekr's key. Treat it as fragile.

---

## 8. RPA (Remote Parking Assist): implemented, but **does not work on EU cars**

### 8.1 Frames

All phone→car frames are **0x0113 RPA_REQ** with the 4-byte block
`[rpaControl, rspaControl, outMode, phoneStatus]`, instType CON, GCM, plus a CMAC trailer.

GCM plaintext = `nSeq(2) ‖ ts(4) ‖ block(4) ‖ CMAC6`, where
`CMAC6 = AES-CMAC(cmacKey, ts(4 BE) ‖ block)[0:6]` (nSeq excluded). The 0x0116 answer works the
same way with `tail = phoneStatus, randX, randY, ansHi, ansLo, gesture`. Lock/unlock 0x0110 has no CMAC.

rpaControl: `00 NONE, 01 REQ_MODE, 02 STOP, 03 OUT_MODE_SET, 04 UNDO, 05 START_SEARCHING_SLOT,
06 START_PARKING_IN, 07 START_PARKING_OUT, 08 PAUSE, 09 CONTINUE, 0B PARK_OUT_REQUEST,
0D PARKIN_REQUEST, 0E PRKG_ON, 0F PRKG_OFF`.
rspaControl (hold-to-move): `01 REQUEST, 02 BACKWARD, 03 FORWARD, 04 BOTTOM_RELEASE, 05 QUIT, 06 COMPLETE`.
outMode (with OUT_MODE_SET): `01 PARALLEL_RIGHT, 02 PARALLEL_LEFT, 03 HEAD_PERP_RIGHT,
04 HEAD_PERP_LEFT, 05 TAIL_PERP_RIGHT, 06 TAIL_PERP_LEFT`.
Modes: RPA=1, RSPA=2, RPA_PLUS=3, RPA_OUT=4.
Status bytes (0x0114/0x0118 tail[0]): `01 PREPARED, 03 CANCEL, 04 QUIT, 05 OFF, 06 COMPLETED,
0xEA(-0x16) OUT_OF_DISTANCE, 0xE8(-0x18) PARKING_IN, 0xE9(-0x17) PARKING_OUT, 0xE0(-0x20) SUSPEND`.
Events: BLUE_UNAUTH 0x3E8, BLUE_DISCONNECTED 0x3EE, INIT_DK_SUCCESS 0x7D0.

**phoneStatus byte** (`PhoneStatusProvider`): `((state&3)<<6) | (((batt%/5)&0x1F)<<1) | signal`.
state: NORMAL 0, BACKGROUND 1, CALL 2 (AudioManager MODE_IN_CALL or IN_COMMUNICATION),
FOREGROUND 3 (unused; foreground maps to NORMAL). battField is clamped to 1..31 (a 0 battery reads
as "dead phone"). signal is always 1. A healthy idle phone gives about 0x21–0x29. The 0x00 value used
earlier was a bug.

### 8.2 CMAC key

`cmacKeyCert` envelope = `L(4 BE) ‖ ephPub(L bytes, 04‖X‖Y, L in 33..120) ‖ ciphertext ‖ tag(16)`.
`SK = ECDH(longTermDkPriv, ephPub).X` (raw 32 bytes, no KDF). AES-**256**-GCM with key=SK,
iv=SK[0:12], aad=SK[12:16]. The plaintext is the 16-byte CMAC key (from libiwallca.so
`ecies_decrypt`@0x1bcf78). If the envelope is missing or the unwrap fails, fall back to
`0x55 × 16` (stock BleConstant.CMACKEY behaviour). The result is cached per session.
Test vectors (`DkCmacTest`):
- key 0x55×16, msg `6aa5db8001000000` (ts‖01 00 00 00) gives CMAC6 `7f07e0ce7d8c`
- key 0x55×16, msg `6aa5db84001234abcd01` gives `ac528db78d10`
- priv d=`00112233445566778899aabbccddeeff00112233445566778899aabbccddee01`, envelope
  `00000041040b61183c1341aa92a9458f788cf5ebcf271922733b4baca8b6cec58eb466090c10479b17b804cfc55d63319b0ad285ba048785b41c0baf42f48e8c15aca72655dba9c3ae915770b73038996d13e2b226b36d5cf41bf576dd7d5243d4c56a7fca`
  unwraps to `000102030405060708090a0b0c0d0e0f`

### 8.3 Challenge answer (`RpaGrid.getAnswer(x,y)` → int16, sent BE)

```
sub=x-y add=x+y mul=x*y div=(y!=0? x/y : 0)   (integer)
x=1:mul | x=3: y in 2..6 ? sub : mul | x=7: y>=8 ? mul : y==4 ? sub : add
x=9: y<=4 ? sub : (y==6||y==14) ? add : mul | x=11,13,17,19: mul
x=15: y==4 ? sub : y in {2,6,12,14} ? add : mul | x=21: y==2 sub, 4 add, 6 div, else mul
otherwise 0
```
Answer only when randX or randY is non-zero. While idle the car streams dummy challenges `00 00`;
stock ignores them, and answering one gets a NAK 0x100A.

### 8.4 Flow (`RpaController`)

1. `begin()`: establish if needed; start the RSSI stream (0x0158 int32 BE every 500 ms from
   `pollRemoteRssi`, while the session is up); poll **REQ_MODE `01 00 00 ps`** every
   `REQ_MODE_POLL_MS=1000`, ignoring NAKs. Never set both lanes in one frame (both lanes was an old
   bug that gave 0x100A). Watchdog `CONNECT_TIMEOUT_MS=20000` with no 0x0117 gives ERROR "Enable
   Remote Parking on the car's centre screen first".
2. On the first 0x0117 SYNC: stop polling, phase READY. Stock additionally gates on
   `prkgModInclnUB==1 && prkgModIncln!=0` (offsets not reversed, TODO).
3. One-shots: startParkIn (06), searchSlot (05), continue (09), pause (08), undo (04), stop (02;
   also stops heartbeat, RSSI and poll). startParkOut(dir) = OUT_MODE_SET(03, outMode=dir) then
   START_PARKING_OUT(07).
4. Hold-to-move (dead-man's switch): `holdMove(fwd)` sends `00 (03|02) 00 ps` every
   `HEARTBEAT_MS=500`. The car halts if a frame is missed. `releaseMove()` cancels it and sends
   `00 04 00 ps`. `gesture` = current rspa direction, echoed in 0x0116.
5. Inbound: 0x0115 with a real challenge gets an auto 0x0116. 0x0114/0x0118 status:
   OUT_OF_DISTANCE or SUSPEND stops the heartbeat; COMPLETED stops it and sets DONE. Only these
   opcodes are parsed for status. Reading the first byte of an 0x0182 push used to stop maneuvers
   about 3/256 of the time.
6. `isBusy` = phase in {CONNECTING, READY, PARKING_IN, PARKING_OUT, MOVING, PAUSED} AND RPA traffic
   within `RPA_IDLE_MS=5000`. Proximity stands down while busy.
7. `blindProbe()`: debug. Sends 13 blocks spaced 1200 ms (PRKG_ON, REQ_MODE, PARKIN_REQUEST, …,
   STOP). It can physically move the car.

### 8.5 Why it fails

The car answers every REQ_MODE with NAK 0x100A and never sends 0x0117, so it never opens the
session. RPA on this platform is absent from the stock Android app (iOS / DK3.0 / UWB-gated), and
the car requires RPA to be armed on the head unit first. The open questions are the CMAC key
(the 0x55 fallback versus the real ECIES key, possibly never valid for EU keys), the 0x0117 field
offsets, and whether EU firmware permits phone RPA at all. The debug `probeRpaStart` (0x0110/0x0A)
is answered with receipt 0x1040 cmdNotSupport.

README's verdict: "the car only authorizes RPA for a **DK 3.0 / Secure-Element key**". The README
and roadmap treat RPA as **closed**, although one line hedges: "DK 3.0 might not be needed, but too
early to conclude". Rewrite advice: keep the codec and crypto (it is test-vectored) behind a debug
flag, and do not ship the UI.

---

## 9. Wear key sync protocol

### 9.1 Transport

Google Play Services **Wearable MessageClient** (transient messages, never DataItems). Phone and
watch apps share the same `applicationId` and signing key, which is what lets the Data Layer route
between them. The channel is encrypted by the Data Layer. **There is no app-level encryption,
authentication or replay protection**: the private key travels as plaintext JSON inside the Data
Layer. Phone receiver: `PhoneKeySyncService : WearableListenerService`. Watch receiver:
`KeySyncService : WearableListenerService`. Both need manifest intent filters for these paths
(manifests were not reviewed here). The target is the first connected node (watch→phone), or all
connected nodes (push/purge/resume).

### 9.2 Paths and payloads

| path | dir | payload |
|---|---|---|
| `/openzeekr/request-key` | W→P | empty |
| `/openzeekr/key` | P→W | UTF-8 JSON `Map<String,String>` of the CLONE_KEYS (§1.1): `{"device_id","priv","pub","cert","dk_id","book_id","digital_key","cmac_key_cert","coef_small","vin","coef_big","mobile_code"}` with prefs values verbatim (base64/hex strings). `"{}"` if the phone is not provisioned |
| `/openzeekr/purge-key` | P→W | empty. Watch: `DkIdentity.wipeAll()`, `ble.disconnect()`, `clearCertPins()` |
| `/openzeekr/status-query` | W→P | empty |
| `/openzeekr/status` | P→W | JSON `{"connected":"0|1","prox":"0|1"}`. connected = !linkSuspended && state in {CONNECTED, SESSION_READY}; prox = `proximityEnabled` only |
| `/openzeekr/pause-link` | W→P | empty (phone releases the link, §6.4) |
| `/openzeekr/link-paused` | P→W | empty (ack) |
| `/openzeekr/resume-link` | W→P | empty |
| `/openzeekr/control` | W→P | `"<WearControl>"` or `"<WearControl>|<arg>"`. Values: CLIMATE_ON (arg = °C, default 22.0; sent as CLIMATE_ZAF with params AC=true, AC.temp="%.1f" Locale.US, AC.duration="15"), CLIMATE_OFF, CHARGE_START, CHARGE_STOP, CHARGE_PORT_OPEN, CHARGE_PORT_CLOSE, FLASH_HORN |
| `/openzeekr/control-ack` | P→W | `"<CONTROL>|ok"` or `"<CONTROL>|err|<reason>"`; a snapshot follows 1.5 s later |
| `/openzeekr/snapshot-query` | W→P | empty |
| `/openzeekr/snapshot` | P→W | JSON `WearVehicleSnapshot {cloudOnline, locked?, soc?, rangeKm?, charging, pluggedIn, portOpen, chargeKw?, acOn, insideTempC?, updatedAt}` |

Watch-side timeouts (`PhoneLink`): status and snapshot 3000 ms, pause 6000 ms, control 12000 ms.
Each conversation uses a single-slot CompletableDeferred, armed before sending.

### 9.3 Lifecycle

- **Push**: on provisioning DONE the phone calls `PhoneKeyPush.pushToWatches` (all connected nodes).
- **Pull**: the watch `MainActivity` onCreate/onResume sends `request-key` when not provisioned.
- **Import**: `DkIdentity.importCredentialBlob` writes each key into the watch's own
  EncryptedSharedPreferences, then `WearKeyState.refresh`, then `ble.setCredential`. The watch is a
  **byte-identical clone** (same deviceId, private key, cert and bookId), so the car sees one
  device, used by one radio at a time.
- **Purge**: on Remove key or sign-out the phone calls `purgeWatches` (best effort, connected nodes only).
- The watch has no cloud account: lock/unlock go over its own BLE (`DkBleManager` +
  `DkLockController(ble.session){ble.refreshSession()}`), and cloud controls are relayed to the phone.

### 9.4 Security notes

Anyone holding the watch has a working car key (the README warns about this). Revocation =
phone `removeKey` (cloud `remove-one-key`), which kills the key car-side for both devices. A watch
that is offline during a purge keeps its copy, but that copy becomes useless once the cloud
revocation reaches the car. The vehicle-cert pin store is per device (`dk_cert_pins`, plain prefs).
The watch pins on its own first handshake.

---

## 10. Quirks, known bugs, TODOs

**Protocol / crypto**
1. **0x1012 reconnect is not implemented.** `establish()` throws on 0x1012 and every connect
   expects 0x1011 (full first-pair). Stock skips the cert exchange on 0x1012 and goes straight to
   the factor exchange (0x0106). This is the first thing to implement for fast reconnects.
2. Static GCM IV for the whole session, with AAD=IV. Nonce reuse is inherent to the car's
   protocol: confidentiality and integrity rest on nSeq/ts. It cannot be fixed client-side.
3. `DkPayload.seq` is a process-global object, reset per `establish()`. It works because there is
   one session.
4. `DkReassembler` ignores fragment indices, has no timeout, and drops stray continuations.
   `DkFrame.decode` does not check the version byte.
5. 0x010B/0x010C and 0x0172/0x0173 failures are only logged. The handshake reports "ready" even if
   the digital key upload failed.
6. 0x0182 is not in `isEncrypted`, so it reaches `appHandler` as raw ciphertext. The RPA handler
   filters by opcode, but any new consumer must do the same.
7. A single `appHandler` slot: `RpaController` registers it in `init`, and any later
   `session.onInbound` replaces it.
8. 0x0159 APPROACHLOCK_NOTIFY and 0x0152 CUST_RESP are not handled. 0x0121 is ACKed but not parsed
   (vehicle status could come from BLE).
9. Stock sends 0x0171 BIG calibration (`BIG_CALIB_APP_CHUNK=220`, defined but never sent). The
   selfCalibHash in 0x0101 is always zeros, even after a table has been captured.
10. CBC_IV, the ECIES envelope layout and the RPA grid were reversed from stock libs and are not
    re-derivable. Copy them as-is.

**Provisioning**
11. `clearProvisioned()` leaves coef_big, mobile_code and vin.
12. Owner account with an existing key-list entry **not** bound to this device: no bind/repush is
    attempted (only the non-owner branch binds). pollCarSync is never called after an owner mint.
13. The phone model is spoofed (`google`/`Pixel 7`) for eligibility and for the coef lookup, so
    the coefs describe a Pixel 7, not the real phone.
14. Only one active app login per account (401/079021). The stock app must be logged out.
15. Never call `sync-key-list` or repush on an AUTHED (3) key: it moves to 5, and BLE then gets 0x1010.

**Proximity / lifecycle**
16. `ProximityController` lock/unlock loops call `disconnect`, `reconnectLast` and `connect`
    **without checking `WearLinkArbiter.linkSuspended`**. During a watch handover, a pending
    walk-away lock or verify could fight the watch for the slot. `forceReconnect` and `resetLink`
    check only `rpaBusy`.
17. The cloud backstop locks on any sustained drop of a session that was up (unless the car is
    already locked or in a zone). A BT glitch at home without zones can cause unwanted locks.
18. `idle-far-lock` (armed-watch timeout path) has no dwell, unlike the onSample lock.
19. `trigger()` is dead code, and `lostReceding`/`lostRssi` are only logged.
20. README's proximity section is **stale** (α=0.4, lock −85, an 8 s "no advertisement" watchdog,
    MAC pinning, "2 s idle → 250 ms burst"). Use the constants in §7 instead.
21. Wear `status.prox` reports only `proximityEnabled`, not calibration or the sub-flags, so the
    watch can stand down needlessly. Per a user report, standing down also requires `connected`.
22. Wear push/purge reach only nodes connected at that moment. There is no retry queue and no
    blob versioning.
23. Bonding uses hidden APIs (`createBond(int)`, `removeBond`, `cancelBondProcess`) via reflection.
    A bond is cleared on every connect.
24. `PhoneStatus.FOREGROUND(3)` is never produced. The foreground state is reported as NORMAL(0),
    which matches stock's packing.

**TODOs in code**
- Parse `prkgModIncln` from 0x0117 (RpaSyncParkPayload offsets).
- Confirm the fragmentation scheme with btsnoop.
- Act on 0x0182/0x0121 as zero-airtime liveness instead of pinging.
- Implement the 0x1012 reconnect, which is the README roadmap item "Faster BLE reconnect".

**Rewrite checklist (minimum viable key)**
scan (filters 0xFDFD / 0x06FE, rnd from the mfr AD), connect via the scanned device, MTU 247,
CCCD on 2A11 (+2A13), 0x0101 CBC confirm, 0x0103 cert, trust + pin, 0x0106 factor, ECDH key/IV,
GCM(AAD=IV) 0x010B, 0x0172, beacon, 0x0110 01/02 with 0x0111 receipt, 0xFFFE ACKs for
0x0121/0x0193/0x0194/0x0138.
