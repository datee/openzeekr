# OpenZeekr rewrite reference

A UI-independent spec of everything the current app does, written from the existing code
(v0.2.9) so the app can be rebuilt from scratch. Where the README or CHANGELOG disagree with
the code, **the code wins** and the difference is noted.

| Doc | Covers |
|---|---|
| [01-cloud-api.md](01-cloud-api.md) | Regions & hosts, login flow, the 4 signing schemes + VIN crypto, ~45 endpoints with exact bodies, vehicle status model, full remote-command catalog, FCM push, user secrets |
| [02-digital-key-ble.md](02-digital-key-ble.md) | DK provisioning (13 key-centre endpoints), BLE UUIDs/adverts, frame layout + CRC, handshake (CBC confirm → cert exchange → ECDH → AES-GCM), opcode catalog, session lifecycle, proximity algorithm with all constants, RPA, Wear key sync |
| [03-features.md](03-features.md) | Every user-facing feature as behaviour (data shown, command called, validation, edge cases), notifications, permissions, storage, i18n, feature status matrix, supported models |
| [04-android-auto.md](04-android-auto.md) | The `:aa` wireless Android Auto MITM: BT/Wi-Fi bootstrap, AA framing + TLS, energy-model injection, cluster HUD video, Waze/speed-camera alerts |
| [05-untapped-capabilities.md](05-untapped-capabilities.md) | What the API/protocol supports but the app doesn't expose: hidden commands, unused status fields, unused BLE opcodes, buildable features, hard limits |

---

## 1. What the system actually is

Four independent capabilities that share one account + one car identity:

```
                     ┌──────────────────────────────────────────────┐
                     │ Account & secrets (user-supplied, encrypted) │
                     └───────────────┬──────────────────────────────┘
          ┌──────────────────────────┼───────────────────────────┬────────────────────┐
          ▼                          ▼                           ▼                    ▼
  A. Cloud control            B. BLE digital key           C. Push / inbox       D. Android Auto
  (TSP gateway,               (offline lock/unlock,        (FCM + message-core,  (optional MITM
   X-SIGNATURE)                proximity, watch)            Azure overseas-app)   proxy, :aa)
```

- **A. Cloud** — 4 backends, 4 signing schemes (see 01 §0). Status is polled; commands are
  "accepted" by the cloud and applied asynchronously by the car, so the only confirmation is a
  short status-poll burst afterwards. No refresh token; one active session per account.
- **B. Digital key** — a software P-256 key enrolled via the cloud once, then everything is
  local BLE: custom framing, ECDH + AES-128-GCM session, control frame `0x0110`
  (sub-byte `01` unlock / `02` lock / …). Proximity is RSSI-driven on the held GATT link.
- **C. Push/inbox** — piggybacks on the stock app's Firebase project; works only if the user
  supplies that config.
- **D. Android Auto** — independent of the car API except for live SoC. Highest legal and
  maintenance risk (see §5).

## 2. Suggested layering for the rewrite

Keep the protocol work pure and testable, and push platform APIs to thin adapters:

1. **Protocol core (no platform deps)** — signing (UC HMAC, X-SIGNATURE, overseas HMAC,
   HF/HMAC-SHA1), VIN AES-CBC, request/response models, command catalog, DK frame codec +
   CRC-16/ARC, fragmenter, handshake state machine, GCM session, proximity decision engine
   (pure function of RSSI samples + motion + config → action). This is ~all of the hard-won
   knowledge and should have **golden-vector tests** captured from a working build.
2. **Services** — session/auth manager (heartbeat + backoff), status poller, command
   dispatcher (BLE-first → cloud fallback), DK link owner (single-slot arbiter for
   phone/watch), push router.
3. **Platform adapters** — HTTP client, BLE central (scan/connect/GATT), secure storage,
   FCM, Wear Data Layer, foreground service, widget, notifications.
4. **UI** — any toolkit; it only talks to (2).

> If you want to do this in Haxe, layer 1 is a good fit for portable Haxe (it's bytes, crypto
> and state machines — you'll need a crypto backend for P-256 ECDH, AES-GCM/CBC, HMAC-SHA1/256,
> RSA-PKCS1 and CMAC). Layers 3–4 need Android-native glue (BLE, FCM, Wear, foreground
> services, widgets), via the HashLink/JNI route or a thin Kotlin shell calling into Haxe.

## 3. Wire details that are easy to get wrong (must preserve)

Collected from the four docs; each is explained in the referenced section.

- TSP `X-SIGNATURE` only verifies if the JSON body is serialized **key-sorted** (01 §3).
- The two HMAC schemes use **different date formats** (short vs full weekday name) (01 §3).
- VIN key/IV are used as **raw ASCII bytes**; `B64:` prefix escape (01 §3).
- Command parameters: dedup by key, **last value wins but first position kept** (RCS parses
  positionally) (01 §6.1).
- `SENTINEL_ON` must be refused unless the car is locked — the cloud returns a hollow 200
  otherwise (01 §6.1).
- SOC is `stateOfCharge` **or** `chargeLevel`; charging is from `chargerState`/power, not
  `isCharging`; charge power ×√3 above 300 V; tyres in kPa (01 §5).
- Temperatures sent as dot-decimal strings; charge limit in **tenths of a percent**; seat
  commands need a 6 s / 500 ms debounce (03 §3, §5).
- DK GCM: session key = X[0:16], IV = Y[0:12] fixed for the session, and **AAD must equal the
  IV** (02 §4). Every car frame needs the plaintext ACK echoing its seq + timestamp (02 §5).
- Phone and watch share the car's **single BLE peer slot** — pause → act → resume with a 45 s
  fail-safe (02 §6).

## 4. Known bugs / gaps in the current app (fix in the rewrite)

| # | Issue | Ref |
|---|---|---|
| 1 | Auto-Sentry on manual lock is not wired (only walk-away lock arms it) | 03 §27 |
| 2 | Temperature unit setting is saved but never applied | 03 §27 |
| 3 | Notification deep links are attached but never handled | 03 §27 |
| 4 | Sign-out doesn't reset onboarding | 03 §27 |
| 5 | Charge port: Charge sheet is cloud-only, widget/watch are BLE-first — unify | 03 §27 |
| 6 | No fast reconnect (`0x1012` already-paired path) — every connect does a full handshake | 02 §10 |
| 7 | Proximity loops can reconnect during a watch handover (handover flag not checked) | 02 §10 |
| 8 | Fragmentation scheme unconfirmed by btsnoop capture | 02 §3 |
| 9 | Region status inconsistent (LA `verified=true` in code, "experimental" in README) | 03 §25 |
| 10 | README proximity constants are stale vs code | 02 §7 |
| 11 | Signing has no tests; login step 4c and push registration sign the same endpoint with different schemes | 01 §9 |
| 12 | Watch receives the DK private key as plaintext JSON (relies only on Data Layer encryption) | 02 §9 |
| 13 | Optimistic UI state with no car readback (fridge, wheel heat, ventilate, widget Sentry) | 03 §27 |

## 5. Scope decisions for the rewrite

**Drop / keep out of v1**
- **Sentry footage / live view** — server-side CN-only (404 `00A01`). Arm/disarm still works.
- **Remote parking (RPA)** — byte-complete but the car NAKs (`0x100A`) software keys.
  Keep the doc; don't ship it.
- **Dead code** — `ControlsScreen`, `SentryScreen`.
- **Android Auto module** — consider a separate, opt-in project. It bundles Google AA
  certificate files, extracts an obfuscated cert/key from the installed Gearhead APK, scrapes
  APKMirror, and uses an accept-all TLS trust manager. These are legal and fragility risks that
  are independent of the car app (04 §7).

**Suggested build order**
1. Protocol core + golden tests (signing, VIN crypto, DK codec/handshake).
2. Login + vehicle list + status poller (EU).
3. Cloud command dispatcher + command catalog.
4. DK provisioning → BLE session → lock/unlock.
5. BLE-first dispatch, foreground link owner, proximity.
6. Charging/schedules/journeys/sharing/OTA/inbox/push.
7. Wear companion, widget, other regions.

## 6. Out of scope of these docs

- No secret values are included (none are in the repo). The constants that do appear (client
  ids, app ids, tenant codes) are the non-secret values already in the source.
- Findings files the code comments cite (e.g. `CMAC_FINDINGS.md`, `SCHEDULE_TRACE_FINDINGS.md`)
  are not in the repo.
- Unverified even in the code: LA/ME login and message-core paths, ME project id/xchanger host,
  RHD/LHD detection.
