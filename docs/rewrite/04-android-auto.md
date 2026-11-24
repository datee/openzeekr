# `:aa` Module — Implementation-Ready Spec (Wireless Android Auto Manipulator)

Package: `io.aawireless.wirelessaamanipulator` (Gradle lib module `aa/`, Java + protobuf-lite).
Namespace `io.aawireless.wirelessaamanipulator`, compileSdk 35, minSdk 26 (feature gated to **Android 13+ / TIRAMISU** at runtime). Protobuf plugin, protoc **4.33.5**, java-lite runtime. Generated proto Java under `androidauto.*` + `io.aawireless.wirelessaamanipulator.proto`.

This is a from-scratch reference. Current UI is irrelevant; it is driven by `:app` only through the few integration points at the end.

---

## 1. What the module does (end to end)

It is a **man-in-the-middle (MITM) proxy for wireless Android Auto projection** between the phone's own Google Android Auto app ("gearhead", pkg `com.google.android.projection.gearhead`) and the car head unit (specifically a **Zeekr** head unit). The phone sits in the middle of its own AA session: it talks to the real car over the car's Wi-Fi/TLS projection link, and it talks to the local gearhead over loopback TCP/TLS, decrypting both ends, relaying frames, and **rewriting / injecting** selected AA protocol messages.

Why: to add features the car + Google Maps don't natively give, by altering the AA message stream:
- **EV energy model injection** — makes Google Maps do EV range/charging routing by faking an `EnergyModel` sensor the car doesn't advertise, derived from a per-model JSON profile + live SoC + live outside temperature.
- **Instrument-cluster HUD takeover** — strips the car's cluster video sink from the service list gearhead sees, and instead streams the app's own H.264 video to the cluster: a "police radar" compass showing Waze police alerts + fixed speed cameras.

### Three simulator roles

The MITM is built from **two `AASimulator` halves** that meet at a shared mediator (`MainTaskService` implements `ServiceThreadPair`). Each half owns one socket + one TLS engine and a read loop; a frame read on one half is translated and pushed to the other.

```
            ┌──────────────────────── PHONE (this app process) ────────────────────────┐
            │                                                                           │
 CAR  <==BT RFCOMM==>  CarHandshakeClient  --(Wi-Fi join)-->  projection TCP+TLS       │
 (Zeekr                (WifiStart/Info/Version                      │                   │
 head-unit)             handshake, WPP)                             ▼                   │
            │                                             PhoneSimulator  ("PhoneToCar")│
            │                                             - TLS CLIENT to the car       │
            │                                             - carSSL engine               │
            │                                                   │  relay/translate      │
            │                                         ServiceThreadPair (MainTaskService)│
            │                                                   │                        │
            │                                             CarSimulator   ("CarToPhone") │
            │                                             - TLS SERVER to gearhead       │
            │                                             - phoneSSL engine, impersonates│
            │                                               the CAR to gearhead          │
 gearhead <==loopback TCP (6288 or 5277)==>                     │                        │
 (local Google AA app)                                          ▼                        │
            │                                     HUD: EnergyModelTranslator,            │
            │                                     ClusterVideoSession, WazePoller, …      │
            └───────────────────────────────────────────────────────────────────────────┘
```

Role naming is from gearhead's point of view:
- **`PhoneSimulator` ("PhoneToCar")** — plays the *phone* toward the real car. TLS **client**. Reads the car's projection stream, decrypts with `carSSL`, relays car→gearhead.
- **`CarSimulator` ("CarToPhone")** — plays the *car* toward local gearhead. TLS **server** (impersonates the head unit, presents the extracted AA cert the way a car does). Decrypts with `phoneSSL`, relays gearhead→car. Can also synthesize car-origin messages (fake battery, sensor responses).
- **`AASimulator`** — common base: single-writer executor, `send(byte[])`, graceful `byeByeAndClose()` (ByeByeRequest → wait ByeByeResponse → close), read-loop lifecycle.
- **`CarHandshakeClient`** (not an `AASimulator`) — the Bluetooth + Wi-Fi *bootstrap* that gets the projection TCP socket open before the simulators exist.

Frames flow: `CarSimulator.read` → `EnergyModelTranslator.process` → `pushToPhone` → `PhoneSimulator.send` (to car), and `PhoneSimulator.read` → translator + cluster hijack → `pushToCar` → `CarSimulator.send` (to gearhead). `pushToPhone` re-encrypts with `carSSL`; `pushToCar` with `phoneSSL`.

---

## 2. Connection flow, step by step

### Constants
- **AA Bluetooth SDP UUID** (RFCOMM service record, used for filtering and connect): `4de17a00-52cb-11e6-bdf4-0800200c9a66` (`BluetoothReceiver.AA_BT_UUID`, `CarHandshakeClient.AA_WIRELESS_UUID`). Socket created with `createInsecureRfcommSocketToServiceRecord`.
- **Legacy projection port** `6288` (`GearheadSettings.LEGACY_PROJECTION_PORT`) — gearhead connects *out* to us after the START broadcast.
- **DHU head-unit-server port** `5277` (`HEAD_UNIT_SERVER_PORT`) — on AA > 17.3 gearhead *accepts* here; CarSimulator connects *in* (user starts it from AA Developer settings).
- **PhoneSimulator fallback listen port** `6299` (when constructed with no socket — `MANUAL_START` test path).
- **AAStarter broadcast** nudges gearhead: implicit broadcast action `com.google.android.apps.auto.wireless.setup.receiver.wirelessstartup.START` to class `...WirelessStartupReceiver`, extras `ip_address="127.0.0.1"`, `projection_port=6288`.
- **WPP BT keepalive**: ping id=8 ~every 1 s; ~400 ms first-ping delay; `POST_VERSION_DELAY_MS = 300` between id=5 and id=2 (Zeekr parser coalescing bug).
- Backoff: RFCOMM connect `BACKOFF_START_MS=700`, `BACKOFF_MAX_MS=15000`. HUS connect timeout 90 s, retry 1 s.

### Phase A — Bluetooth trigger (`BluetoothReceiver`)
1. Receiver (exported) listens for `ACL_CONNECTED`, `ACL_DISCONNECTED`, `ACTION_UUID`, and A2DP `CONNECTION_STATE_CHANGED` (`android.bluetooth.a2dp.profile.action.CONNECTION_STATE_CHANGED`, also registered dynamically by the service since it isn't manifest-exempt from the API-26 implicit-broadcast ban).
2. Gated: no-op if `SDK_INT < TIRAMISU`; no-op unless `AA_SETTINGS/aa_enabled == true`.
3. On connect: SPECIFIC mode (`SelectionStore` has a pinned MAC) fires only for that MAC; ANY mode fires for any device that advertises `AA_BT_UUID` (or is in `KnowDevicesStore`, or after async `fetchUuidsWithSdp` → `ACTION_UUID`). It does **not** gate on the digital key being nearby.
4. Starts `MainTaskService` via `startService()` (plain started service; rides under `:core`'s single FGS `ProximityService`), passing `EXTRA_DEVICE_ADDRESS` / `EXTRA_DEVICE_NAME`.
5. A2DP reconnect while ACL stayed up is treated as a "fresh session" signal. ACL set tracked so projection auto-reconnect can distinguish a projection drop (ACL still up → stay alive) from a real BT drop (ACL gone → teardown).

### Phase B — BT RFCOMM WPP handshake (`CarHandshakeClient`, a Thread)
Frame format over RFCOMM (and over the WPP-TCP control channel): `[u16 BE length][u16 BE messageId][payload]` (NOT the AA transport framing). Messages are `AndroidAutoBluetooth.proto` (proto2, pkg `androidauto.bluetooth.proto`). Message ids (from the `.proto` comments):

| id | message | direction | role |
|----|---------|-----------|------|
| 1 | WifiStartRequest `{ip_address, port}` | car→phone | car's projection endpoint |
| 2 | WifiInfoRequest `{}` | phone→car | ask for Wi-Fi creds |
| 3 | WifiInfoResponse `{ssid, key, bssid, security_mode, access_point_type}` | car→phone | Wi-Fi creds |
| 4 | WifiVersionRequest `{major,minor,supported_channels,HeadUnitInfo,WifiProjectionProtocolInfo}` | car→phone | version + optional WPP-over-TCP endpoint (wire field 6 `{ip,port}`) |
| 5 | WifiVersionResponse `{major,minor,device_serial,status,WifiDeviceInfo{device_id,connectivity_lifetime_id}}` | phone→car | phone identity |
| 6 | WifiConnectStatus `{status,error_message_hint}` | phone→car | joined AP OK |
| 7 | WifiStartResponse `{ip_address,port,status}` | phone→car | ack projection start |
| 8 | WifiPingRequest `{timestamp}` | both | keepalive |
| 9 | WifiPingResponse `{timestamp}` | both | keepalive echo |

`WifiStatus`: SUCCESS=0, plus negative error codes (e.g. INCORRECT_CREDENTIALS=-3).

Handshake logic (reader-driven, synchronous reply):
1. Ensure Wi-Fi enabled (`WifiEnabler`).
2. On **id=4** (WifiVersionRequest): reply **id=5** echoing the car's version on BT (do NOT downgrade — Zeekr drops a bare response), with hardcoded identity: `DEVICE_SERIAL="WAAM0000001"`, `DEVICE_ID="a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"`, `CONNECTIVITY_LIFETIME_ID="f0e1d2c3-b4a5-4968-8776-5a4b3c2d1e0f"`, status SUCCESS. Then after 300 ms delay proactively send **id=2** to drive the car to send creds. Start 1-Hz id=8 keepalive. (Over WPP-TCP it answers version as 6.1 and skips creds.) Remembers the version-6 endpoint for WPP-over-TCP.
3. On **id=3** (WifiInfoResponse): learn ssid/key, callback `onWifiCredentials`, then **async** join Wi-Fi (`WifiConnector.connectWpa2`, `WifiNetworkSpecifier`, WPA2, 25 s timeout). Joins per-socket (never `bindProcessToNetwork` globally).
4. On Wi-Fi join: send id=6 SUCCESS, callback `onWifiConnected`, then open projection TCP if the endpoint (id=1) is known, else `startWppOverTcp`.
5. On **id=1** (WifiStartRequest): learn car endpoint ip/port (`"0.0.0.0"`/empty → resolve the car's own AP address: DHCP server, else IPv4 route gateway). Reply **id=7** SUCCESS. If already joined, open projection TCP now and reply **id=6** SUCCESS; callback `onBootstrapComplete`.
6. **Open projection TCP** (`openTcpOverWifi`): transient `bindProcessToNetwork(carNet)` around a plain `Socket.connect(ip,port,5000)` (EPERM workaround for `WifiNetworkSpecifier` socket factory), restore binding in finally, up to 4 retries. On success: stop BT keepalive, set `projectionActive=true`, call `service.onTcpConnected(socket)` → the simulators get built.
7. **WPP-over-TCP variant** (Peugeot-style, kept generic): if the version request advertised an endpoint, connect to `carAP:port` over the car network, do a plain TLS handshake on the socket (phone = TLS **server**, `setWantClientAuth`, TLSv1.2, presenting the AA cert), close RFCOMM, and run the same id-based WPP framing/pings over TLS. The car's id=1 then arrives over TCP.

Projection-drop handling: `onProjectionDropped()` clears `projectionActive` but keeps RFCOMM + reader alive, so the car can re-drive a session (resend id=1) without a full reconnect. `CarHandshakeClientManager.startOrSwitch` enforces a single client per device.

### Phase C — Projection AA session (built in `MainTaskService.onTcpConnected`)
1. Reset per-session state (`ClusterInfo.reset()`, `EnergyModelTranslator.sensorChannel=null`).
2. Build `CarSimulator` (gearhead side) if not present → either binds `6288` + `AAStarter` broadcast + nudges up to 4× until gearhead connects, OR (AA>17.3) connects out to `127.0.0.1:5277` (DHU head unit server), retrying up to 90 s.
3. Build `PhoneSimulator` with the projection socket (car side).
4. Start the HUD (`startHud`): WazePoller + HudState + ClusterVideoSession (if `replace_maps`), GATSO cache load.

### AA transport handshake inside each simulator
The AA projection stream uses the **AA transport framing** (section 4), TLS-encapsulated. Bring-up (plaintext version frames, then TLS):
- **CarSimulator** (to gearhead): sends car "hello" `00 03 00 06 00 01 00 04 00 01` = channel 0, flags 3 (plain+control), len 6, msgId 1 (VERSION_REQUEST), **version 4.1**. Reads gearhead's VersionResponse. Builds `NioSSL` as **server** (`phoneSSL`), keystore `"keystore"` (res/raw) for the base engine but the real presented identity is the extracted AA cert via `sslEngineBuilder`. Marks `ready`.
- **PhoneSimulator** (to car): reads the car's VersionRequest `00 03 00 06 00 01 MM MM mm mm` (expects msgId 1, len 6), replies VersionResponse `00 03 00 08 00 02 MM MM mm mm 00 00` (msgId 2, status 0, echo the car's version). Uses the **extracted AA KeyStore** (`CertProvider.getKeyStore`), builds `NioSSL` as **client** (`carSSL`). Marks `ready`.
- Each waits for the peer's `isReady`, then relays. `MESSAGE_AUTH_COMPLETE` is left to the normal AA control flow (not sent manually). `handshakeready()` → `CarHandshakeClient.sendWiFiStartCompleted()` (id=7).

---

## 3. TLS, certificates, trust

### Raw cert resources (`aa/src/main/res/raw/`) — purpose only
All PKCS12/PFX, password `"aa"`, alias `"aa"`, issuer "Google Automotive Link":
- **`aaorg.pkcs12`** — subject `O=CarService` (the genuine AA client-cert *subject* a real phone presents); expires 2026-06-24. The "real" AA identity shape; strict head units (Zeekr) want this subject.
- **`keystore.pkcs12`** — subject `O=Google-Android-Reference`; expires 2044. The base engine keystore `CarSimulator` loads by name `"keystore"`. A permissive reference cert.
- **`google.pkcs12`** / **`gg.pfx`** — identical to each other, subject `O=Google-Android-Reference`, expires 2044. Spare/legacy reference identities (not referenced by name in current code paths other than as spares).

Important: these bundled certs are accepted by no-name head units but **rejected by Zeekr**, which is why the runtime extraction below exists. There is intentionally **no static-keystore fallback** in `CertProvider`.

### Cert extraction pipeline
- **`CertProvider`** — single source of the phone-side KeyStore. Order: in-memory cache → cached `aa_extracted_cert.p12` in filesDir (valid by expiry only, 1-day grace; prefs `aa_cert_cache`) → fresh extraction from the installed gearhead APK. On failure it throws `CertUnavailableException` and sets `AppStatus.CertSource.EXTRACTION_FAILED` (no fallback). `refreshFromLatestApkIfDue()` downloads a newer APK from APKMirror when the cached cert is within 30 days of expiry (throttled 1/day) and replaces the cache if the new cert outlives it. `invalidate()` forces re-extraction.
- **`AACertExtractor`** — on-device port of `aa-cert-extractor`. Given gearhead APK path(s): (1) scan every `classes*.dex` raw string pool for the leaf cert PEM (`-----BEGIN CERTIFICATE-----`, skipping the known hardcoded `ROOT_CERT`); (2) minimal DEX reader (`DexScan`) shortlists classes with ≥2 static `byte[]` fields (the encrypted-key + salt holder); (3) `DexClassLoader` (parent = **boot** classloader, not app — avoids Compose VerifyError collisions) loads candidates and reads the byte arrays by reflection; (4) `decryptPrivateKey`: `ObfuscationUtils.deobfuscate` over cert+ROOT_CERT+salt, derive AES-256 key+IV from first 48 bytes, `AES/CBC/PKCS5Padding` decrypt, strip 28-byte prefix + 54-byte tail, Base64 NO_WRAP → PKCS8 RSA key. Builds PKCS12 `{alias "aa"}` with chain `[leaf, ROOT_CERT]`. Expected leaf subject `CN=CarService`. `ROOT_CERT` is the hardcoded Google Automotive Link root (2014–2044) baked into the class.
- **`ObfuscationUtils`** — verbatim byte-math deobfuscation (do not "clean up"); 48-byte inner loop XOR scheme keyed by salt.
- **`GearheadApkDownloader`** — APKMirror scraper (fragile, best-effort). `BASE=https://www.apkmirror.com`, app page `/apk/google-inc/android-auto/`. Chain: app page → highest `android-auto-MA-MI-BU-release` slug → first `*-android-apk-download/` variant → `/download/?key=…` button → `/wp-content/themes/APKMirror/download.php?id=..&key=..` → file (plain APK or `.apkm`/`.apks`/`.xapk` bundle; unwraps the base APK). Manual redirects, cookie jar, desktop Chrome UA, downloads via `Net` (cellular, never the car AP). Rejects downloads <1 MB.
- **`sslEngineBuilder`** — builds SSLEngine/SSLContext from a KeyStore (key pw "aa"), **TLSv1.2** (+TLSv1.1 on the engine), `setNeedClientAuth(true)`, trust manager = `adb`.
- **`adb`** — a **no-op `X509TrustManager`**: `checkClient/ServerTrusted` do nothing, `getAcceptedIssuers` returns empty. All peer certs are accepted (MITM requires it; the car's cert is logged, never validated).
- **`NioSSL` / `NioSslPeer`** — hand-rolled NIO `SSLEngine` wrap/unwrap over `InOutStream`; `encrypt(msg, msgId, flag)` prepends the 2-byte msgId for FIRST/ALL frames; `decrypt(buf,pos,len)`. The handshake encapsulates records in frames with header `00 03 LL LL 00 03` (channel 0, flags 3, msgId 3 = `MESSAGE_ENCAPSULATED_SSL`). `close()` frees the native context.
- `NoSSLv3SocketFactory` present (forces non-SSLv3) but not referenced on the active paths.

---

## 4. AA message framing (`AAMessage`, `AAFraming`)

Transport frame = `[u8 channel][u8 flags][u16 BE bodyLen][ (u32 BE totalSize if FIRST) ][body]`.
- Flags byte combines: fragment bits `FLAG_ALL=3` (single), `FLAG_FIRST=1`, `FLAG_MIDDLE=0`, `FLAG_LAST=2`; `FLAG_CONTROL=4`; `FLAG_ENCRYPTED=0x08`.
- **Channel ids** (`Constants`): CONTROL=0, INPUT=1, SENSOR=2, VIDEO=3, MIC=4, AUDIO_MEDIA=5, AUDIO_SYSTEM=6, AUDIO_TTS=7, BLUETOOTH=8, MEDIAINFO=9, NAVINFO=10, GENERICNOTIFICATION=11. (These are nominal defaults; actual service/channel ids come from the car's ServiceDiscoveryResponse at runtime — e.g. Zeekr cluster sink id ≈ 21, its input ≈ 22.)
- On parse: encrypted body → `NioSSL.decrypt`; else copied raw. For ALL/FIRST frames the first 2 bytes of the decrypted body are the big-endian `messageId`, then the proto payload.
- `getFormated(ssl)`: encrypt (or plain), build header, FIRST frames carry the 4-byte decrypted-total.
- **`AAFraming.buildFrames`** fragments **after encryption** (AA body cap 16384): single frame if ciphertext ≤ `MAX_FRAME_BODY=16376`, else FIRST(+4-byte total)/MIDDLE/LAST with each chunk independently encrypted; plaintext chunk `FRAG_PLAINTEXT_CHUNK=15000`. Caller must hold the `ssl` monitor across build+write (TLS records are sequence-numbered).
- **`InOutStream`** reads whole frames (header 4 bytes, +4 if FIRST); socket mode uses a `DataInputStream` with 10 s read timeout, TCP_NODELAY, keepAlive. USB/PFD mode uses a queue (`ByteArrayHandler`) and `getNext`.

### Message types / enums (`AndroidAuto.proto`, proto2, `java_outer_classname=Protos`)
- **ControlMessageType** (channel 0): VERSION_REQUEST=1, VERSION_RESPONSE=2, ENCAPSULATED_SSL=3, AUTH_COMPLETE=4, SERVICE_DISCOVERY_REQUEST=5, SERVICE_DISCOVERY_RESPONSE=6, CHANNEL_OPEN_REQUEST=7, CHANNEL_OPEN_RESPONSE=8, CHANNEL_CLOSE=9, PING_REQUEST=11, PING_RESPONSE=12, NAV_FOCUS_*=13/14, BYEBYE_REQUEST=15, BYEBYE_RESPONSE=16, AUDIO_FOCUS_*=18/19, CAR_CONNECTED_DEVICES_*=20/21, SERVICE_DISCOVERY_UPDATE=26, UNEXPECTED=255, FRAMING_ERROR=65535.
- **SensorMessageId**: REQUEST=32769, RESPONSE=32770, BATCH=32771, ERROR=32772.
- **MediaMessageId** (video): DATA=0, CODEC_CONFIG=1, SETUP=32768, START=32769, STOP=32770, CONFIG=32771, ACK=32772, MIC_*=32773/4, VIDEO_FOCUS_REQUEST=32775, VIDEO_FOCUS_NOTIFICATION=32776, UPDATE_UI_CONFIG_*=32777/8, AUDIO_UNDERFLOW=32779.
- **SensorType** incl. `SENSOR_FUEL`, `SENSOR_VEHICLE_ENERGY_MODEL_DATA`; `FuelType.FUEL_TYPE_ELECTRIC`; `EvConnectorType` (MENNEKES, COMBO_2…). Video enums: `VideoCodecResolutionType` (VIDEO_800x480…), `MediaCodecType.MEDIA_CODEC_VIDEO_H264_BP`, `DisplayType.DISPLAY_TYPE_CLUSTER`, `VideoFocusMode.VIDEO_FOCUS_PROJECTED`.
- Key messages: `ServiceDiscoveryResponse{repeated Service services}`, `Service{id, sensor_source_service, media_sink_service, input_source_service, navigation_status_service, …}`, `SensorSourceService{Sensor{sensor_type}, supported_fuel_types, supported_ev_connector_types}`, `MediaSinkService{display_type, display_id, video_configs}`, `VideoConfiguration{codec_resolution, width/height_margin, ui_config{margins,content_insets}}`, `NavigationStatusService{type IMAGE|ENUM, image_options{w,h,colour_depth}}`, `SensorBatch{repeated fuel_data, location_data, energy_model}`, `LocationData{latitude_e7, longitude_e7, bearing_e6, speed_e3}`, `FuelData{fuel_level, range, low_fuel_warning}`, cluster video `Setup/Start/Stop/Config/Ack`, `VideoFocusRequest/Notification`, `ChannelOpenRequest/Response`, `ByeByeRequest/Response{ByeByeReason}`.

**Messages modified / injected by the MITM:**
- **ServiceDiscoveryResponse** (car→gearhead) rewritten: add a `SENSOR_FUEL` + `SENSOR_VEHICLE_ENERGY_MODEL_DATA` sensor (+ EV fuel/connector types) if absent; strip the cluster video sink + its input service (so gearhead never claims the cluster).
- **SensorRequest** `ENERGY_MODEL` (gearhead→car) rewritten to `FUEL` (so the car answers with a real SoC).
- **SensorBatch** (car→gearhead) rewritten to append a synthesized `EnergyModel` (computed from SoC %); location_data tapped for the HUD.
- **Cluster video**: the full `ChannelOpen/Setup/Config/VideoFocus/Start/CODEC_CONFIG/DATA/Ack` sequence is injected by the phone on the cluster channel (gearhead no longer knows it).
- Dummy-battery test mode synthesizes SensorResponse/SensorBatch directly in `CarSimulator`.

---

## 5. Features

### 5.1 Energy model injection
Goal: make Google Maps show EV range/charging routing by advertising an `EnergyModel` sensor the Zeekr doesn't natively expose, and feeding a plausible battery/consumption model.

- **`EnergyModelTranslator`** (the message processor run on every relayed frame):
  - Patches `ServiceDiscoveryResponse`: captures cluster info, finds the sensor service, records its channel id into `sensorChannel`, injects FUEL + ENERGY_MODEL sensors, loads the selected JSON profile, strips cluster services.
  - On `SensorRequest(ENERGY_MODEL)` from gearhead → rewrites to `SENSOR_FUEL` (the car has no energy model, but it has fuel/SoC).
  - On `SensorBatch` from the car → reads `fuel_data[0].fuel_level` as SoC %, reads `location_data` (feeds `OutsideTempService.updateLocation` + `CarLocationStore`), appends a synthesized `EnergyModel` built from the profile + SoC + outside temp/air density.
- **`EnergyProfiles`** — registry of 10 selectable per-model JSON profiles in `res/raw`, pref key `energy_profile` in `AA_SETTINGS`, default `zeekr_7gt`. Keys/files: `zeekr_001_rwd_100`, `zeekr_001_awd_100`, `zeekr_001fr`, `zeekr_7gt`, `zeekr_7gt_lr`, `zeekr_7gt_75`, `zeekr_7x`, `zeekr_009_116`, `zeekr_009_140`, `zeekr_x`.
- **`EnergyModelFromJson`** — builds `Ev.EnergyModel` from the JSON; applies the signed `offset_value` (clamped −10..10) tuning: common factor `1 − offset/100` scales road-load constant/linear and losses, quadratic scaled by that factor squared. `batteryLevelWh = capacity * soc/100`. HVAC status set to `HVAC_MAX_AC_ON`. Outside temp + air density from `OutsideTempService`.
- **`EnergyModel`** — older procedural `setup(...)`/`create(...)` model (constant/linear/quad maps across −20/0/30/40 °C, mass scaling, regen, charging curves). **Superseded by the JSON path** (only commented-out `setup(...)` calls remain in the translator); keep as reference, not the live path.

**JSON profile schema** (`ev.proto` mirror, proto2 pkg `androidauto.ev.proto`, imported by AndroidAuto.proto). Root `{type:"ENERGY_MODEL", uuid, name, data:{…}}`; `data`:
- `vehicleInfo`: `massKilograms.mean`, `batteryLevelWh.mean`, `batteryCapacityWh.mean` (strings), `referenceAirDensity` (float ~1.293), `externalTempCelsius` (float) — all `*WithUncertainity{mean[,standard_deviation]}` wrappers.
- `roadLoad`: `constant.mean`, `linear.mean`, `quadratic.mean` (FloatWithUncertainity).
- `drivetrainLosses.drivetrainPowerLoss[]`: each `{speedMetersPerSecond, lossAtPower[]{powerWatts, lossWatts.mean}}` (~10 speeds × ~50 power points).
- `maxRegenPower.regenerationRateAtEnergyLevel[]`: `{energyLevelWh, regenerationRateWatts}` (~26).
- `batteryLosses.batteryPowerLoss[]`: `{powerWatts, lossWatts.mean}` (~30).
- `auxiliaryDrainAtTemp[]`: `{tempCelsius (−22.5..47.5), hvacDrainWatts (bytes/str), batteryConditioningDrainWatts (bytes/str), totalDrainWatts.mean}` (~15).
- `chargingCurves.chargingCurveAtPower[]`: `{inputPowerWatts (1440..480000), timeToFullBattery[]{energyToFullWh, timeToFullSecs}}` (~9 power levels × ~22 points).
- `currentChargingTime.timeRemainingSecs`.

### 5.2 Cluster video / HUD
Owns the instrument-cluster display by stripping its sink from the SDR and streaming H.264 to it.
- **`ClusterInfo`** — static capture of the car's cluster capabilities from SDR: `NavigationStatusService` (IMAGE vs ENUM, size, colour depth), `MediaSinkService` with `DISPLAY_TYPE_CLUSTER` video sink (service id, every `VideoConfiguration` indexed exactly as the car lists them, usable = H.264 Baseline), paired input service (same display_id), safe insets (margins + content insets), `openTriggerChannelId` (highest id gearhead still opens — used to time our channel-open). `reset()` per session.
- **`ClusterVideoSession`** — supervisor thread driving the AA A/V handshake **as the phone**: wait for gearhead's channel-opens to go quiet → `ChannelOpenRequest(videoCh)` → `ChannelOpenResponse` → `Setup{H264_BP}` → `Config{READY, cfgIdx, maxUnacked}` → `VideoFocusRequest{PROJECTED}` → `VideoFocusNotification` (grant; `FOCUS_GRANT_FALLBACK_MS=2500` fallback) → `Start{session, cfgIdx}` → CODEC_CONFIG(SPS/PPS) + DATA(8-byte BE ptsUs + H.264) with ACK flow control (`maxUnacked`, keyframes never dropped). Re-arms on focus bounce (new session id), re-establishes on stall (`STREAM_STALL_MS=4000`, `HANDSHAKE_TIMEOUT_MS=6000`). Opens paired input channel (absorbed, unused). Observes car messages on cluster channels and consumes them. `setOnStreaming` fires GATSO update once streaming (off the video path).
- **`ClusterVideoEncoder`** — MediaCodec H.264 AVC Baseline, byte-buffer mode, bitmap→YUV420 (BT.601). Config from `HudConfig`: 800×480, 10 fps, 600 kbps, 3 s keyframe interval. Join-before-release teardown ordering (avoids native use-after-free SIGSEGV). Does NOT set PREPEND_HEADER (SPS/PPS kept as the separate CODEC_CONFIG message).
- **`CompassRenderer`** — renders the HUD bitmap: forward semicircle "radar" (car at bottom pointing up), range rings at 5 km, markers placed by bearing-relative-to-heading + distance, police shield / amber camera icons, distance labels, report-count badges, Waze poll status line, caption "traffic / incident monitor". Draws only inside the car's safe inset area. Also has `encode(bmp, PNG|RAW_RGB565|RAW_ARGB8888)` for the alternate IMAGE-cluster route.
- **`HudState`** — merges Waze alerts (`WazePoller`) + nearby cameras (`CameraStore`, within 8 km, max 40) into the marker set every 2 s; detects a marker first entering the forward 5 km radar and fires `WarningSound`.
- **`HudMarker`** — unified POI (POLICE / SPEED_TRAP / CAMERA) with lat/lon, reports, publish time, speed.
- **`HudConfig`** — knobs: `ownCluster`, `testPattern`, `openClusterInput`, encoder size/fps/bitrate/keyframe, `resendCodecConfig`.
- **`CarLocationStore`** — latest vehicle lat/lon/bearing/speed, fed from the AA `LocationData` sensor stream (NOT phone GPS — zero battery cost). `hasFix()`, `ageMillis()`.
- **`Geo`** — haversine distance, bearing, relative bearing, metre offsets.

### 5.3 Waze police alerts
- **`WazeClient`** — OpenWeb Ninja Waze endpoint `https://api.openwebninja.com/waze/alerts-and-jams?bottom_left=…&top_right=…&alert_types=POLICE&max_alerts=N&max_jams=0`, header `x-api-key`. Parses `data.alerts[]` (POLICE only): `alert_id, type, subtype, latitude, longitude, publish_datetime_utc, num_thumbs_up`. 429/403 → `QuotaException`.
- **`WazePoller`** — background loop polling a ±10 km box around `CarLocationStore`. Interval from `waze_interval_sec` (floor 15 s, default 300). Next-allowed time **persisted** (`waze_next_allowed_millis`) so reconnects can't burn quota; exponential error backoff (cap 30 min), 429/403 backs off 60 min; skips if fix stale (>30 s). Max 50 alerts.
- **`WazeTester`** — "Test Waze call" button logic: runs the exact same query (prefers car AA fix, falls back to phone last-known), returns OK/fail message with masked key.
- **`PoliceAlert`** — trimmed Waze alert; `isSpeedTrap()` when subtype contains "CAMERA".
- API key resolution: `AA_SETTINGS/waze_api_key`, else `BuildConfig.WAZE_API_KEY` (from `local.properties` `WAZE_API_KEY`).

### 5.4 Fixed speed cameras (`GatsoUpdater`, `CameraStore`)
- **`GatsoUpdater`** — keeps the fixed-camera dataset current from GitHub release feeds. Each feed publishes a `csv_files.zip` asset containing `GATSO_ALL.csv` (Garmin-POI rows `lon,lat,"max @<speed>","<CC> Radar <type>"`). Default sources `1e1/Open-GATSO-POI` (EU+Canada) and `apgneto/br-open-speedcameras` (Brazil); user-editable list in `AA_SETTINGS/camera_sources`. Uses GitHub `releases/latest` API, caches per-repo CSV in filesDir keyed by release tag, re-downloads only on tag change, rebuilds the merged store. Network via `Net` (cellular).
- **`CameraStore`** — in-memory parallel-array index (~26k points), parses CSV, `nearby(lat,lon,range,max)` with a cheap bounding-box prefilter before haversine.

### 5.5 Outside temperature service (`OutsideTempService`)
- Open-Meteo `https://api.open-meteo.com/v1/forecast?latitude=…&longitude=…&current=temperature_2m,relative_humidity_2m,surface_pressure`. 15-min scheduler, location from the AA sensor stream, computes **air density** (Magnus vapor-pressure formula) for the energy model's `referenceAirDensity`, and caches temp/density in prefs (`outside_temp_service`). `setTemp()` overrides for the dummy-battery test.

### 5.6 Other stores / helpers
- **`SelectionStore`** (`aa_device_selection/selected_address`) — ANY vs SPECIFIC trigger device.
- **`KnowDevicesStore`** (`known_bt_devices/addresses`) — remembered AA-capable device MACs (skip UUID recheck).
- **`GearheadSettings`** — gearhead version parsing (`needsHeadUnitServer` = AA > 17.3 → 5277 path), deep-links to AA settings, advice strings (native wireless must be OFF; start head unit server). Notes there's no API to read gearhead's wireless toggle, so repeated RFCOMM connect failures are the heuristic.
- **`AppStatus`** — process-wide status bus (cert source, connection stage, advice) the UI + log bridge observe.
- **`WarningSound`** — plays the default notification ringtone as `USAGE_ASSISTANCE_NAVIGATION_GUIDANCE` (so AA routes it to car speakers), 3 s min interval.
- **`Net`** — opens HTTP bound to a validated **cellular** internet network (never the car's internet-less AP).

---

## 6. Android components, permissions, lifecycle

### Manifest (library manifest, merges into `:app`)
- **Permissions**: ACCESS_NETWORK_STATE, BLUETOOTH, BLUETOOTH_ADMIN, BLUETOOTH_CONNECT, BLUETOOTH_SCAN, ACCESS_FINE/COARSE/BACKGROUND_LOCATION, ACCESS_WIFI_STATE, CHANGE_WIFI_STATE, NEARBY_WIFI_DEVICES, CHANGE_NETWORK_STATE, INTERNET, READ_BASIC_PHONE_STATE, SYSTEM_ALERT_WINDOW, POST_NOTIFICATIONS, WAKE_LOCK, TURN_SCREEN_ON, DISABLE_KEYGUARD.
- **`<queries>`** `com.google.android.projection.gearhead` (so the APK can be read for cert extraction).
- **No launcher activity** (the old MainActivity is replaced by `:app`'s Compose tab).
- **Components**:
  - `BluetoothReceiver` (exported) — ACL connect/disconnect, UUID, A2DP state. Starts/stops the service.
  - `WifiEnableActivity` (not exported, `showWhenLocked`, `turnScreenOn`, translucent, singleInstance, noHistory) — wakes the screen over the keyguard to surface the Wi-Fi panel.
  - `MainTaskService` (not exported) — **plain started service, NOT a foreground service** (rides under `:core`'s `ProximityService` FGS to stay alive). `START_NOT_STICKY`.

### Service lifecycle (`MainTaskService`)
- `onCreate`: install crash-file logger, register dynamic A2DP/ACL receiver.
- `onStartCommand`: `ACTION_STOP` stops; `MANUAL_START` builds a self-loop test pair; otherwise resolves the device, `CarHandshakeClientManager.startOrSwitch` → BT handshake, `HandshakeCallbacks` fire the Wi-Fi/endpoint/bootstrap progress.
- On creds (id=3) → `startCarSide()` once (`carLaunched` guard): build CarSimulator + (6288 broadcast/nudge or 5277 connect).
- On projection TCP (`onTcpConnected`) → build PhoneSimulator, `startHud()`, optional dummy-battery scheduler (`dummy_battery`, `VALUE_1`=temp, `VALUE_2`=battery%).
- Projection drop while BT ACL up → `teardownProjectionLayer()` (ByeBye both links, keep RFCOMM + Wi-Fi, idle wait); real BT drop → full teardown + `stopSelf`.
- `onDestroy`: stop schedulers, stop HUD, ByeBye both links (bounded), stop simulators, close both TLS engines, shutdown handshake client (releases Wi-Fi + nulls cached Network). **Never kills the process** (co-hosted with the key service).
- `WifiConnector` registers a `NetworkCallback` (WPA2 `WifiNetworkSpecifier`), per-socket routing only, drops the cached `Network` on `onLost`.

### Wakefulness
`WifiEnabler`/`WifiEnableActivity` handle the Android-10+ reality that apps can't toggle Wi-Fi: foreground/unlocked → open the Wi-Fi panel; background+locked → launch the showWhenLocked activity (allowed via SYSTEM_ALERT_WINDOW) to surface it over the keyguard. First connection needs the user awake+unlocked to approve the system "join the car's Wi-Fi" dialog.

### `:app` integration points
- `App.kt` on startup: `AaCertMaintenance.maintain()` + `installLogBridge()`.
- `AaCertMaintenance` — gates on `AA_SETTINGS/aa_enabled` + TIRAMISU; runs `CertProvider.getKeyStore` + `refreshFromLatestApkIfDue` off-main; bridges `AppStatus` → the app's `Logx` shareable log.
- `AndroidAutoScreen.kt` (Compose tab) — drives the same `AA_SETTINGS` prefs: master `aa_enabled`, `offset_value`, `replace_maps`, `waze_api_key`, `waze_interval_sec`, `energy_profile`, `camera_sources`. Buttons call `WazeTester.run`, `CertProvider.invalidate/getKeyStore`, `GearheadSettings.openAndroidAutoSettings`, `GatsoUpdater` repo add/remove. Shows the cert card only on `EXTRACTION_FAILED`, and the live `AppStatus` connection stage.
- **All shared prefs store `AA_SETTINGS`** (byte-identical keys to the original app). Other stores: `aa_cert_cache`, `known_bt_devices`, `aa_device_selection`, `gatso`, `outside_temp_service`.

---

## 7. Legal / fragility / quirks / TODOs

### Legal / redistribution risks
- **Bundled Google AA certs** (`aaorg.pkcs12` etc., issuer "Google Automotive Link", subject "CarService"/"Google-Android-Reference") are Google's own projection certs redistributed in the APK — clear copyright/EULA exposure. A rewrite should rely on runtime extraction only, not ship these.
- **On-device cert extraction** from the installed gearhead APK (`AACertExtractor` + the hardcoded `ROOT_CERT`) is reverse-engineering Google's obfuscated key material — the whole point of the obfuscation is to stop this.
- **APKMirror scraping** (`GearheadApkDownloader`) violates their ToS, is anti-bot-fragile (every HTML/redirect/key change breaks the chain), downloads ~150 MB, and spoofs a desktop browser UA.
- **GitHub GATSO feeds** — third-party speed-camera datasets; legality of camera-location apps varies by jurisdiction (illegal in some countries, e.g. parts of the EU).
- **Waze via OpenWeb Ninja** (not official Waze API) — ToS + quota risk; police-alert surfacing may be regulated.
- **MITM of a TLS session with a no-op trust manager** (`adb`) — accepts any cert; the app is deliberately defeating AA's mutual TLS. Impersonating the car to gearhead and the phone to the car.

### Fragility
- Zeekr RFCOMM parser coalesces frames → the 300 ms `POST_VERSION_DELAY_MS` and careful one-frame-per-read; brittle across firmware.
- `openTcpOverWifi` EPERM `bindProcessToNetwork` workaround is device/ROM-specific.
- Cert extraction heuristic ("class with ≥2 static byte[]", boot-classloader parent, fixed 28/54-byte slicing, decrypt-any-ordering) breaks on any gearhead obfuscation change — rich diagnostic errors acknowledge this.
- AA > 17.3 killed the 6288 START broadcast → requires the user to manually start the DHU head unit server (5277); native Wireless AA must be OFF (unreadable, inferred from connect failures).
- Cluster video handshake timing (open-trigger channel, focus fallback, stall re-establish, silent-black SPS/PPS resend) is full of car-specific workarounds; `HudConfig` flags exist precisely because behavior varies.
- Energy profiles: masses + frontal areas are estimates; aero term approximate (noted in `EnergyProfiles` javadoc).

### Quirks / TODOs in code
- `MainTaskService.MANUAL_START` + dummy-battery (`VALUE_1`/`VALUE_2`) are test scaffolding.
- `Constants.FLAG_ALL`/`FLAG_CONTROL` carry `// ToDo check usage!`.
- `EnergyModel` (procedural) is dead relative to `EnergyModelFromJson` (JSON) — keep JSON path.
- `OutsideTempService.fetchTemperatureC` spawns an empty throwaway thread (vestigial).
- `NoSSLv3SocketFactory` unused on active paths.
- Projection auto-reconnect is marked EXPERIMENTAL (car drives the session; phone-initiated rebuild doesn't work).
- CarSimulator advertises AA version **4.1** to gearhead; handshake echoes versions elsewhere — keep per-peer version handling.
