# OpenZeekr — App-level Functional Spec (for a from-scratch rewrite)

Source of truth: repo `/home/user/openzeekr` at `4c02777` (Release 0.2.9, versionCode 21).
Scope: the `:app` module (UI, widget, force-unlock, push, wear phone-side, SendToCar), `AndroidManifest.xml`s,
`core/.../{Deps,DepsHolder,AppForeground}.kt`, `core/.../util/*`, `res/xml`, README / CHANGELOG / docs / scripts.
Cloud API internals (`core/net`, `core/remote`), BLE digital key (`core/ble`) and the `:aa` Android Auto module are
covered by other documents and are only *referenced* here by the function names the UI calls.

Conventions in this doc:
- `deps.X.y()` = a call on the DI container (`com.openzeekr.app.Deps`). All repository calls are `suspend` and
  return `CallResult<T>` = `Ok(value)` | `Err(message)`.
- `Command.X` = an entry of the cloud command catalog (`core/remote/Command.kt`, serviceId + start/stop + params).
- "Cloud" = TSP REST; "BLE" = digital-key (DK) session. `deps.vehicleControl.send(cmd)` = **BLE-first, cloud-fallback**
  dispatcher; `deps.control.send(cmd, extra)` = **cloud only**.
- Status field paths refer to `VehicleStatusBean` (`basicVehicleStatus`, `additionalVehicleStatus.{electricVehicleStatus,
  drivingSafetyStatus, climateStatus, maintenanceStatus}`). Booleans arrive as strings: lock `"1"`=locked/`"0"`=unlocked;
  doors/trunk/hood `"0"`=closed, anything non-blank-non-"0" = open.

---

## 0. App architecture (what to reproduce)

### 0.1 Modules
| Module | Role |
|---|---|
| `:app` | Phone Compose UI, Glance widget, FCM service, force-unlock activity, SendToCar activity, Wear Data-Layer phone side. Depends on `:core` and `:aa`. |
| `:core` (Android library, namespace `com.openzeekr.core`) | All logic: config/secrets (`ConfigStore`, `SecretsConfig`, `Units`), cloud (`net/*`, `remote/*`), BLE DK (`ble/*`, `ble/rpa/*`), push registrar, util (logging, notifications, log crypto, native secrets). Declares all permissions + `ProximityService` + BLE/activity receivers in its manifest (merged into `:app` and `:wear`). Builds JNI lib `libozsecrets.so`. |
| `:wear` | Standalone Wear OS companion (shares `:core`). Out of scope except the phone-side protocol (§17). |
| `:aa` | Android Auto "Enhancement" (wireless AA manipulator, Waze HUD, speed cameras, EV routing). Driven by the Android Auto tab (§19). |

### 0.2 DI: `Deps` (manual container, one per process)
`App : Application, DepsHolder` constructs `Deps(this)` in `onCreate`. Any component reaches it via
`(applicationContext as DepsHolder).deps` (used by widget callback, force-unlock activity, wear service, `ProximityService`).
`DepsHolder` lives in `:core` so `:core` services don't depend on the app module.

`Deps` members (construction order matters):
| Member | Type / purpose |
|---|---|
| `appScope` | `CoroutineScope(SupervisorJob() + Dispatchers.Main)` — process-lifetime scope for fire-and-forget work that must outlive a screen/activity. |
| `appVersion` | installed `versionName` (for update check). |
| `updateAvailable: MutableStateFlow<ReleaseInfo?>` | newer GitHub release or null. `checkForUpdate()` runs once at construction (quiet, offline-tolerant). |
| `authAlert: AuthAlertState` | "session rejected" state; `showBanner` true after `BANNER_AFTER = 3` consecutive auth rejections. `onAuthOk()`, `onAuthRejected(code)`. |
| `recheckAuth: SharedFlow<Unit>` + `requestAuthRecheck()` | wakes heartbeat backoff immediately ("Re-check now"). |
| `config: ConfigStore` | encrypted single-JSON config (`EncryptedSharedPreferences` file `openzeekr_secure_config`, key `config_json`). On build: applies `Logx.setHttp(logHttp)`, `Logx.setBle(logBle)`. |
| `apiClient: ApiClient` | HTTP client; `onEndpointChanged()` → `apiClient.rebuild()` after region/base-URL/project changes. |
| `auth: AuthRepository` | `login()`. |
| `control: RemoteControlRepository` | `send(cmd, extra)`, `status()`, `controlState()`, `vehicleInfo()`, `trafficReport()`, `renameVehicle(name)`. |
| `sentry: SentryRepository` | events / prepareDownload / liveToken (CN-only, UI hidden). |
| `journey: JourneyRepository` | `trips(page, startMs?, endMs?)`, `loggingEnabled()`, `setLogging(on)`, `trackpoints(...)`. |
| `inbox: InboxRepository` | `messages(page, pageSize=30)`, `unreadCount()`, `markRead(id)`, `markAllRead()`. |
| `ota: OtaRepository` | `checkUpdate()`, `startDownload()`, `install(now, scheduledTime?)`, `cancel()`. |
| `share: ShareRepository` | `pending()`, `respond(invite, accept)`, `myShares()`, `revoke(grant)`, `createShare(email)`. |
| `pendingInvites: MutableStateFlow<List<ShareInvite>>` + `refreshInvites()` | invites addressed to us (no-op when logged out). |
| `nav: NavRepository` | `sendToCar(lat, lon, name, address, city)`. |
| `push: PushRegistrar` | `registerIfLoggedIn()`, `onNewToken(token)`, `disableOnLogout()`. |
| `schedule: ScheduleRepository` | `chargePlan()`, `setChargePlan(...)`, `departures()`, `createDeparture/updateDeparture/deleteDeparture(setting)`. |
| `vehicleState: VehicleStatusHolder` | live status `StateFlow<VehicleStatusBean?>`; `start()/stop()` poll; `refresh()`; `refreshAfterCommand()` (burst at ~1.5 s, ~4 s, ~8 s, deduped); `lastError`. Poll 20 s parked, 5 s when engine on / moving. |
| `capabilities: CapabilityHolder` | per-VIN `StateFlow<VehicleCapabilities>`; `reload()`, `ensureLoaded()`. Flags used by UI: `fridge`, `frunk`, `tailgate` (powered), `sunroof`, `sunshade`, `seatCool`, `rearSeatCool`, `windows`, `engineRes`, `rpa`, `chargeCover`. |
| `ble: DkBleManager` | DK GATT manager; `state` (SCANNING/CONNECTING/CONNECTED/SESSION_READY/ERROR…), `connect(mac?, diagnostic)`, `disconnect()`, `session.ping()`, `session.control(byte)`, `resetHandshakeBackoff()`, `hasCredential`, `lastError`, `pollRemoteRssi`. |
| `vehicleControl: VehicleControl` | BLE-first/cloud-fallback dispatcher (§0.4). |
| `dkIdentity: DkIdentity` | device id (also written to `config.deviceIdentifier`), credential, `isProvisioned`, `exportCredentialBlob()`. If a credential exists it is armed into `ble`. |
| `provisioning: DkProvisioning` | `state` (step CERT→BIND→KEY_LIST→KEY_INFO→DONE, `message`), `provision(owner)`, `removeKey()`, `passiveState()`, `fetchCccPairingCode()`. |
| `lock: DkLockController` | BLE `lock()/unlock()` with self-healing session refresh; `probeRpaStart()`. |
| `phoneStatus`, `rpa: RpaController` | Remote parking (dev only, non-functional). |
| `calibTest: CalibrationTestController` | at-car 4-position calibration walk; car-side passive-entry toggles. |
| `motion: MotionMonitor` | still/moving for proximity cadence. |
| `sentryAutoArm: SentryAutoArmer` | `armIfLockedOutsideZones(trigger)`, `currentLocation()`, `phoneZoneStateFast(zones)`, `isPointInAnyZone(...)`. |
| `proximity: ProximityController` | approach-unlock / walk-away-lock policy; wired with lambdas: `cloudLock`, `cloudIsLocked`, `rpaBusy`, `onWalkAwayLocked` (→ auto-Sentry), `cloudLockState` (verifies lock + lists open parts), `notifyLockAlert` (SECURITY channel, stable id), `isInExclusionZone` (phone fix first → car cloud position fallback → fail toward acting). |

`AppForeground.isForeground` (volatile flag in `:core`): set by `App`'s activity-lifecycle counter; read by BLE phone-status byte.

### 0.3 Application lifecycle (`App.onCreate`)
1. `CarNotifier.ensureChannels(this)` — create all car-notification channels before FCM can auto-display.
2. `deps = Deps(this)`.
3. Register `ForegroundTracker` (counts started activities). First start → `AppForeground.isForeground = true` + `startHeartbeat()`; last stop → false + `stopHeartbeat()`.
4. `ForceUnlockManager.init(this)` — registers runtime `ACTION_SCREEN_ON` receiver (§11).
5. `AaCertMaintenance.maintain(this, appScope)` — only if AA feature enabled and API ≥ 33: load/refresh AA cert on IO.
6. `AaCertMaintenance.installLogBridge()` — mirrors `:aa` `AppStatus` into `Logx` (tag `aa`).

**Online heartbeat** (foreground-only, NOT in the FGS): loop while foreground:
- if logged in → `AccountLogin(config).heartbeat()` (`ms-app-online-manager/app/hb`; the car only executes cloud commands for the "online device").
  - success → reset interval to 30 s, `authAlert.onAuthOk()`.
  - auth rejection (HTTP 401 / TSP `079020`) → `authAlert.onAuthRejected(code)`, interval doubles up to 240 s.
  - other failure → keep 30 s.
- logged out → reset, `onAuthOk()`.
- wait `withTimeoutOrNull(interval) { recheckAuth.first() }` so "Re-check now" bypasses backoff.
- `startHeartbeat()` also calls `vehicleState.start()`; `stopHeartbeat()` calls `vehicleState.stop()` (status polling is foreground-only).
- Manual cloud commands also send a heartbeat immediately before firing (inside `RemoteControlRepository`).

### 0.4 Command dispatch rules (reproduce exactly)
`VehicleControl.send(cmd, extra)`:
- BLE byte mapping: UNLOCK 0x01, LOCK 0x02, FLASH_HORN 0x03 (car locator), FRONT_TRUNK 0x04 (hood), TRUNK_UNLOCK 0x06, TRUNK_LOCK 0x07,
  WINDOW_OPEN 0x0D, WINDOW_CLOSE 0x0C, CHARGE_LID_OPEN 0x13. Everything else → cloud. WINDOW_VENT deliberately cloud (0x12 is cabin vent).
- BLE used only if a byte is mapped AND `extra` is empty AND `ble.state == SESSION_READY`; waits 1.5 s for `CONFIRMED`; any other result → cloud fallback.
- Cloud `RemoteControlRepository.send`: heartbeat first; commands with `requiresLocked` (SENTINEL_ON) are refused client-side when the car reports unlocked (issue #41).

Generic UI feedback pattern (`fire(label)`): snackbar "label…" → result snackbar "label ✓" or "label failed: msg"; on success `vehicleState.refreshAfterCommand()`.
`fireQuiet(label)` (used inside climate/fridge sheets): no progress/success toast, only failure; still `refreshAfterCommand()`.

### 0.5 Navigation shell (`MainActivity` → `AppRoot`)
- `MainActivity`: `enableEdgeToEdge()`, `setContent { OpenZeekrTheme { AppRoot(deps) } }`. Single activity, no Navigation-Compose graph (tabs are an enum + `when`).
- Theme: **dark only** (`darkColorScheme`), font scale clamped at **1.30×**. Brand tokens: accent `#5AA9FF`, energy (amber) `#F5B740`, neon `#31E08A`, good `#46D8A0`, crit, surface2/3, line, muted, faint.
- **Gate 1**: `!cfg.onboardingDone` → full-screen Onboarding (§1); on finish set `onboardingDone = true`.
- `AppBootstrap(deps, serviceEnabled = loggedIn && provisioned)` (§20.2) runs permission prompts and starts/stops `ProximityService`.
- Tabs (enum order): **Vehicle, Location (Parking), Security, Schedule, Key, Updates, Android Auto, Settings**. Updates hidden unless `cfg.isOwner`. Sentry tab exists in code but is not in the enum (hidden).
- Default tab recomputed on `(loggedIn, provisioned)`: logged-out → Settings; logged-in but no key → Key; else Vehicle. If current tab becomes hidden → Vehicle.
- Bottom bar: fixed 78 dp items, horizontally scrollable when they don't fit, chevrons appear when scrollable in that direction (tap scrolls 2 items).
- Top bar: brand badge; car name (`cfg.carNickname` or default) — tappable dropdown when `cfg.vehicles.size > 1` (multi-car switcher); pencil → rename dialog; subtitle "VIN •••XYZ" (last 3) or "name your car" hint; bell with unread badge (caps "99+"); connection pill:
  - BLE ready (CONNECTED or SESSION_READY) & logged in → "BLE + Cloud" (good); BLE only → "BLE"; logged in → "Cloud" (accent); else "Offline" (faint).
- Global session signals (from `net/SessionSignal`): `loggedInElsewhere` (TSP 079021, token already cleared) → snackbar "signed out — account active elsewhere"; `sessionExpired` (079012) → snackbar "Session expired — please sign in again". Both reset after showing.
- On `prov.step == DONE` → `PhoneKeyPush.pushToWatches(ctx)` (arm watch automatically).
- **Multi-car switch**: `config.setActiveVehicle(vin)` → `vehicleState.refreshAfterCommand()` + `capabilities.reload()` + snackbar "Switched to X". Labels: `v.name` or "VIN •••1234"; active item prefixed.
- **Rename car**: dialog; saves `carNickname` and the matching `vehicles[].name`; if non-blank also `control.renameVehicle(n)` (cloud, fire-and-forget).
- **Share invitation dialog**: shows first of `pendingInvites` (model or "a Zeekr" + "…VIN last4", owner name, granted functions, "until <date>" (epoch s/ms tolerant), explainer). Accept/Decline → `share.respond(invite, accept)`; Ok → snackbar, drop from list, on accept `vehicleState.refresh()` + `capabilities.reload()`, then `refreshInvites()`; Err → snackbar. Dismiss (outside tap) = "decide later" (drop locally). Buttons disabled while busy. Invites refreshed on login and whenever unread count refreshes.
- **Update-available dialog** (§18): once per new release version.
- **One-time support note** ("hello" dialog) after onboarding if `!cfg.supportNoteShown`: "Support" opens `https://revolut.me/emilimpd`; either button sets `supportNoteShown = true`.
- Inbox is a full-screen takeover (`showInbox`) replacing the scaffold; on back → refresh unread.

---

## 1. Onboarding / first-run setup

Steps (progress bar "Step n of N"): **WELCOME → REGION → [SECRETS only if `!cfg.secretsValid`] → LOGIN → KEY**. Back button on all but first.

| Step | Data / actions | Gate for Next |
|---|---|---|
| Welcome | 3 bullets (log in, set up key, done) + "authorized use only" note. | always ("Get started") |
| Region | Chips for `Region.ALL` = **EU, SEA, LA, ME**. Tap different → `config.setRegion(code)` (repopulates gateway hosts / projectId / country / SNS region) + `deps.onEndpointChanged()`. Shows "verified" vs "experimental" (red) + warning for unverified. Text tells which `zeekr_key_extractor --region` value to use (`extractorRegion`: EU→EU, others→EM). | always |
| Secrets | Multiline paste field for `zeekr_secrets.json` → `config.importJson(text)`: Ok → `onEndpointChanged()`, "Imported"; Err → "Import failed: msg". Shows "keys valid" when `secretsValid`. | `secretsValid` |
| Login | Email + password (`LoginField`: autofill content types Username+EmailAddress / Password, IME Next/Done; Done submits). Sign-in: persist ONLY email/password onto live config (`config.update { copy(email, password) }`), then `auth.login()`. Ok → autofill `commit()` (password-manager save) + "Logged in"; Err → "Login failed: msg" and reveals **Share log** button (`shareEncryptedLog`). While on this step HTTP logging is force-enabled (restored on leave) so failed logins are always captured. When logged in shows a card with email + VIN. | `loggedIn` (accessToken non-blank) |
| Key | If provisioned: "Key ready". Else "Set up key" → `provisioning.provision(owner = cfg.isOwner)` (owner vs shared path from vehicle-list at login). Busy while step ∈ {CERT, BIND, KEY_LIST, KEY_INFO}; shows `prov.message`. | "Skip for now" always; "Finish" only when provisioned. Both call `onDone`. |

Validation rules for secrets (`SecretsConfig.secretsValid` / `validate()`): `hmac_access_key`, `hmac_secret_key`, `password_public_key`, `prod_secret` required; `vin_key` / `vin_iv` must be exactly 16 UTF-8 bytes if set (unless `vin_key` starts with `B64:` — LA format); `overseas_access_key` and `overseas_secret_key` both set or both blank. VIN is NOT required (it is a login result).
JSON import shape = `secrets.example.json` (keys: hmac_access_key, hmac_secret_key, password_public_key, prod_secret, vin_key, vin_iv, overseas_access_key, overseas_secret_key, email, password, vin; also xchanger_sign_secret, inbox_auth_secret). Import merges only non-blank fields.
Build-baked secrets: if `secrets.properties` existed at build time, values are compiled into the native lib (`NativeSecrets`) and `SecretsConfig.SECRETS_BAKED` is true → Secrets step skipped and Settings hides the secrets/import-export cards.

Edge: sign-out (`signedOut()`) does **not** reset `onboardingDone` (comment claims it does — the user lands on Settings, not the wizard).

---

## 2. Vehicle tab (dashboard)

### 2.1 Data loading
- Keyed on active VIN (`LaunchedEffect(cfg.vin)`): clear `info`; `capabilities.reload()`; `vehicleState.refresh()`; `control.vehicleInfo()` → `VehicleInfo` (model, colorName, nickName, rightHandDrive) — if car has a nickname and local `carNickname` is blank, adopt it; `control.trafficReport()` → eSIM data plan (best-effort, hidden on error).
- Live status from `vehicleState.state` (poll owned by App foreground).
- Model → `CarCatalog.forModel(info.model)`; paint → `CarCatalog.colorFor(model, info.colorName)` (§16).

### 2.2 Derived state (exact rules)
- `locked` = `centralLockingStatus == "1"`; **null → treated as locked**.
- SOC = `stateOfCharge` if non-blank else `chargeLevel` (this platform leaves stateOfCharge blank).
- Range = `distanceToEmptyOnBatteryOnly` (if non-blank and ≠ "0") else `basicVehicleStatus.distanceToEmpty`; converted with `Units.distance`.
- Charging = `elec.chargingActive` (derived from live `chargeIAct × chargeUAct`, NOT the `isCharging` flag); power kW = `chargePowerW/1000`; phases `chargePhases`; ETA `timeToFullyCharged` minutes.
- Plugged = `elec.pluggedIn`; port open = `elec.chargePortOpen`.
- Driving = `engineStatus` non-blank and ≠ "engine-off", OR `speed > 0`. Hero speed = `Units.speedValue(kmh, distanceUnit)` + "km/h"/"mph".
- A/C on = `climate.acOn`; target = `climate.crSetTemp` else locally remembered target (default 22.0 °C, prefs `climate_prefs/target_temp_c`). Heating if interiorTemp < target → sun icon (energy), else snowflake (accent).
- Windows: `climate.windowsVenting` (cracked) → "Vent"; `windowsOpen` → "Open"; else "Windows".
- Trunk open = `trunkOpenStatus` non-blank and ≠ "0".

### 2.3 Layout content (UI-independent)
1. **Auth alert banner** (when `authAlert.showBanner`): "Session rejected — usually wrong region" + "Re-check now" → `deps.requestAuthRecheck()`; button shows spinner until alert state changes.
2. **Hero**: animated 3D hero (§16.2) when `Hero3dAssets.available(model.key)` (7GT, 7X packs) AND `info` loaded; else classic hero card (paint-gradient card + white render from `assets/cars/`, charging "breathe" overlay, paint name / "Driving" + speed badge; neutral loading card + spinner while `info == null` to avoid flashing a wrong car).
3. **Stat row**: Central lock (Locked/Unlocked), Battery %, Range, Avg consumption (`elec.avgConsumption`, 1 decimal, "Ø" kWh/100km).
4. **Quick-action grid** (4 columns, reflow, short last row centred). Tiles:
   | Tile | Action |
   |---|---|
   | Lock/Unlock (state-aware) | `vehicleControl.send(LOCK/UNLOCK)` (toggle of current `locked`). |
   | Climate | opens Climate sheet (§3). |
   | Charge ("Charge & more" / "Plugged in" / "6.4 kW · 3-phase" + countdown ring) | opens Charge sheet (§5). Countdown ticks locally every second from `timeToFullyCharged`, re-anchored on each poll; "H:MM" ≥1 h else "M:SS". |
   | Windows | opens Windows sheet. |
   | Flash + honk | `vehicleControl.send(FLASH_HORN)` (BLE-first) + hero flash animation. |
   | Flash | `vehicleControl.send(FLASH)` (cloud only; no honk-only command exists). |
   | Trunk (always shown, **no confirmation**) | command: open & powered tailgate → `TRUNK_LOCK` (label "Close"); BLE session ready → `TRUNK_UNLOCK` (BLE pops boot, label "Open"); powered tailgate (`caps.tailgate`) → `TRUNK_OPEN` (RDU_2, "Open"); else `TRUNK_UNLOCK` (cloud latch release, label "Unlock"). |
   | Fridge (only `caps.fridge`) | opens Fridge sheet. |
   | Frunk (only `caps.frunk`) | `vehicleControl.send(FRONT_TRUNK)`. |
5. **Tyre pressure** 4 cells (FL/FR/RL/RR from `maintenanceStatus.tyreStatus{Driver,Passenger,DriverRear,PassengerRear}` in kPa) converted to bar/psi/kPa; warn colour if < 220 kPa.
6. **Connectivity** (if traffic report has any of used/total/remain, GB): remaining < 1 GB → warning colour.
7. **Vehicle stats** (if any present): odometer, 12 V battery (`lowVoltageBattery`, warn < 11.9 V), service distance (`distanceToService`), service due (`daysToService`: ≥60 → months, else days).

### 2.4 Windows sheet
Windows: Open (`WINDOW_OPEN`), Vent (`WINDOW_VENT`), Close (`WINDOW_CLOSE`) — current state highlighted. Sunroof (only `caps.sunroof`): `SUNROOF_OPEN/CLOSE`. Sun-shield/sunshade (only `caps.sunshade`): `SUNSHADE_OPEN/CLOSE`. All via `vehicleControl.send`; sheet closes *before* firing (so the snackbar is visible); triggers hero animation.

### 2.5 Fridge sheet (`caps.fridge`)
- State: on/off persisted locally (`climate_prefs/fridge_on`, default false — car has no reliable readback; fix #79), target °C persisted (`fridge_temp_c`, default 5), "constant temperature" mode (session-local, default true).
- Temp −/+ in 1 °C steps, range −6…50 °C.
- ON → `control.send(FRIDGE_ON, [operation=1, zae.model=(1 const|0), zae.temp="%.1f" Locale.US])`; OFF → `FRIDGE_OFF` (operation=0). Temp/mode changes debounced 600 ms and sent only while ON (otherwise just stored). Uses `fireQuiet`.

---

## 3. Climate controls (Climate sheet)

All via `control.send(...)` (cloud) with `fireQuiet`.
- **Readout**: cabin temp (`interiorTemp`), outside temp (`exteriorTemp`), always shown in °C.
- **Target temperature** stepper: 0.5 °C steps, range 15.5…28.5 °C. Seeded from remembered target. Changes persisted immediately (home glyph) and sent **debounced 600 ms** as ONE command: `CLIMATE_ZAF` with `AC=true`, `AC.temp="%.1f"` (**dot-decimal, Locale.US** — car rejects comma), `AC.duration=15`.
- **Climate power**: if `acOn` → `CLIMATE_ZAF [AC=false]`; else `CLIMATE_ZAF` with on-params.
- **Rapid cool**: set target 16.0 → debounced A/C-on at 16 (active when acOn && temp ≤ 16). **Rapid heat**: target 28.0 (active when acOn && temp ≥ 28). (#24)
- **Ventilate** (session-local toggle): `CABIN_ON` / `CABIN_OFF` (RCC).
- **Steering-wheel heat** (session-local toggle, no readback): `STEER_WHEEL_ON` / `STEER_WHEEL_OFF`.
- **Defrost** (state from `climate.defrostOn`): `DEFROST_ON` / `DEFROST_OFF`.
- **Seats** (4 tiles; positions: driver 11, passenger 19, rear-left 21, rear-right 29). Each has Heat and (if capability) Cool/Vent; each cycles 0→1→2→3→0; heat and cool mutually exclusive on a seat.
  - Seed from status: heat `drvHeatSts/passHeatingSts/rlHeatingSts/rrHeatingSts`; cool `drvVentDetail/passVentDetail/rlVentDetail/rrVentDetail`.
  - Optimistic level; status re-seeds only if > **6 s** since last tap (prevents stale readback snapping back, 0.2.8 fix).
  - Taps debounced **500 ms** → ONE command with final level:
    - heat n>0: `CLIMATE_ZAF [SH.<pos>=true, SH.<pos>.level=n, SH.<pos>.duration=15, SV.<pos>=false]`; n=0: `[SH.<pos>=false]`.
    - cool n>0: `[SV.<pos>=true, SV.<pos>.level=n, SV.<pos>.duration=15, SH.<pos>=false]`; n=0: `[SV.<pos>=false]`.
  - Front cool shown only if `caps.seatCool`; rear cool only if `caps.rearSeatCool` (fail-closed; 7GT Privilege has heat-only rear). **Seat ventilation is a differentiator vs the stock app.**
- Not exposed in live UI (catalog only): ENGINE_START/STOP (RES), FRAGRANCE_ON/OFF, AC_ON/AC_OFF generic, SEAT_HEAT_ON/OFF generic, LOCKER_ON/OFF, HONK. (They were shown in the now-unreferenced `ControlsScreen` debug grid.)

---

## 4. Lock / unlock / signals (summary)
| Action | Path |
|---|---|
| Lock / Unlock | `vehicleControl.send(LOCK/UNLOCK)` (BLE 0x02/0x01 → cloud RDL/RDU `door=all`). |
| Flash+horn | BLE 0x03 → cloud RHL `horn-light-flash`. |
| Flash only | cloud RHL `light-flash`. |
| Trunk / frunk / charge port | see §2.3 and §5. |
| Glovebox / visitor | §8. |
Gap: in the live UI a **manual lock does NOT trigger auto-Sentry** (only walk-away lock does via `ProximityController.onWalkAwayLocked`). The auto-arm-on-manual-lock code only exists in the unused `ControlsScreen`. CHANGELOG 0.2.3 claims manual lock arms it too — rewrite should call `sentryAutoArm.armIfLockedOutsideZones("manual lock")` after a successful LOCK.

---

## 5. Charging (Charge sheet + Schedule tab)

### 5.1 Charge sheet (from the Charge tile; reachable unplugged)
- Header: SOC %, state ("6.4 kW · 3-phase" / Charging / Plugged in / Unplugged).
- **Charge limit slider**: visual 0–100, drag clamped ≥ 50, 5 % snapping (steps=19), floor tick at 50. Seeded from `cfg.chargeLimitPct` (default 80; car has no reliable readback). On release: `pct = roundToInt()` (fix #46: 60/90 not 59/89) → `control.send(SET_CHARGE_SOC, [soc = pct*10])` (tenths of %), then persist `chargeLimitPct`.
- **AC charge current (DEV MODE ONLY)**: 5…32 A stepper; seed `acSettingCurrent` → `round(chargeIAct)` → 16; "Apply" → `SET_CHARGE_CURRENT [rcs.ac.current=n]`. Known not honoured on EU 7GT (capability acRange=0).
- **Battery pre-conditioning** toggle (checked = `hvBatteryPreHeatingActive`) → `BATTERY_PREHEAT_ON/OFF` (ZAN).
- **Charge port**: Open (`CHARGE_LID_OPEN`, disabled when open) / Close (`CHARGE_LID_CLOSE`, disabled when closed). (Sheet uses cloud `control.send`; widget/wear use `vehicleControl` → BLE 0x13 for open.)
- **Start/Stop charging**: `CHARGING_ON [rcs.restart=1]` / `CHARGING_OFF [rcs.terminate=1]`.
- All via `fire("Charge")` with toast feedback.

### 5.2 Schedule tab
Loads on open: `schedule.chargePlan()` and `schedule.departures()` (snackbar on error). Footer note: schedules are stored car-side; car must be awake to save; confirmed only when the car acks.

**Off-peak charging window** (serviceId ZAZ, single window):
- Fields: enabled (`plan.command == "start"`), start time (default 22:00), end time (default 06:00), "keep charging past end time if limit not reached" (`plan.target == "1"`), hidden `timerId` (default "2") and `scheduledTime` reused from read-back.
- Time pickers: platform 24 h `TimePickerDialog` → "HH:mm".
- Save → `schedule.setChargePlan(enabled, startTime, endTime, keepCharging, timerId, scheduledTime)`. No immediate re-GET (car syncs asynchronously); keep local state. Snackbar result.

**Departure plans** ("booking travel", serviceId ZAO, fixed car-side slots):
- Row shows: time ("HH:mm" from first enabled cycle time, else from `temporaryTime` "yyyy:MM:dd:HH:mm:ss", else "--"), active day letters (Mon..Sun, wire day 1=Mon…7=Sun), "Preheat" tag if `preHeatSts == 1`, name, on/off switch (`sts`), delete icon.
- Toggle → `updateDeparture(d.copy(sts=on?1:0).sanitizedForWrite())`; **optimistic** (no re-GET; car may be asleep).
- Delete → `deleteDeparture(d.sanitizedForWrite())` = disables the slot; local `sts=0`.
- Add (dialog): name (default "Departure"), time (default 08:00:00), day chips (FlowRow so Sat/Sun don't clip), cabin climate toggle (default on), battery preheat toggle (default on). Create enabled only when ≥1 day. → `createDeparture(newRecurringDeparture(...))` → reload list.
- **Write-body rules** (car-side validation; must be reproduced):
  - `btId ≥ 1` (create uses 1), `bookingType = 1` (recurring), `sts=1`, `displaySts=1`.
  - `temporaryTime` must be a REAL next occurrence "yyyy:MM:dd:HH:mm:00" of the earliest selected weekday at `time` (roll a week if today's slot passed); placeholder "2099:12:12:08:00:00" only as last resort — the car rejects placeholders with FCM 6074 "too close to departure time" (#36).
  - `cycleTimes`: all 7 days, `sts=1` for picked days, `time` "HH:mm:00".
  - `csSetting{duration=10, sts=cabin?1:0, temp="22.0"}` always present; `ventiSettings` (locations 1,2) and `heatSettings` (locations 1,2,3,5) and `whlSetting{duration=10, level=2, sts=0}` always present (disabled) because the serializer drops empty/null and the server requires them.
  - `sanitizedForWrite()` on edit/delete: fill missing blocks, clamp btId, recompute `temporaryTime` anchor for recurring plans.

---

## 6. Journeys + CSV export
Entry: Security tab → "Journey log" (owner-only). Full-screen with back.
- **List**: `journey.trips(page)` (page size 10 server-side; repo auto-retries ~20× on the flaky 504ing trail service). Reload = page 1; "Load more" = next page; de-dup by `"${reportTime}-${tripId}"`. Errors: initial → full error state + Reload; load-more → snackbar.
- **Trip card**: date, start–end clock, distance (unit-converted), start→end place (reverse-geocoded via `Geocoder`, cached per rounded 4-dp lat/lon, falls back to coords), duration ("Xh Ym"), avg speed km/h, end odometer km, consumption, regeneration. Tapping opens Google Maps directions `https://www.google.com/maps/dir/?api=1&origin=..&destination=..&travelmode=driving`.
- **Record trips switch**: read `journey.loggingEnabled()` (null = unknown); toggle → optimistic, `journey.setLogging(on)`, revert on error, then re-read to confirm (vehicle-relayed).
- **Export CSV** (enabled when list non-empty): range dialog — Last 30 days / 3 months (90) / 6 months (180) / 12 months (365) / Custom (Material DateRangePicker; end = end-of-day). Walks pages 1..N (`trips(page, startMs, endMs)`) until `!hasMore` or 200-page cap; on page failure stops and exports what it has, with "partial (n trips)" snackbar; empty → "no trips"/"none (failed)".
- **CSV format**: every cell double-quoted with `"` escaped as `""`, `\n` line endings. Columns (localized headers): Date (`d MMM yyyy`), Start (`HH:mm`), End, From ("lat, lon" 5 dp, Locale.US), To, Distance (<unit>) (bare number, unit km/mi), Avg consumption, Energy regen, Duration, Odometer, Route (Google Maps URL).
- File: `cacheDir/exports/zeekr-journeys-yyyyMMdd.csv`, shared via `FileProvider` (`${applicationId}.fileprovider`, `cache-path exports/`) with `ACTION_SEND` `text/csv` + read grant.

---

## 7. Location / map / navigation handoff ("Location" tab, a.k.a. ParkingScreen)
- **Where's my car**: map (MapLibre GL + OpenFreeMap style `https://tiles.openfreemap.org/styles/liberty`, no API key, no Play Services) centred on `basicVehicleStatus.position.{latitude,longitude}`, zoom 15.5, **non-interactive** (gestures off), recentres on every status update (follows car live). Pin overlay at centre. `vehicleState.refresh()` on open.
- **Navigate to car**: `google.navigation:q=lat,lng` targeted at `com.google.android.apps.maps`; fallback `geo:lat,lng?q=lat,lng(My Zeekr)`. Disabled "Location unavailable" when no position.
- **Remote parking (DEV MODE only)** — see §9.
- The map component also has a `ZonePickerMap` (interactive, fixed centre crosshair, radius circle scaled by metres-per-pixel; reports centre on camera idle; initial zoom 16 or world view 2) used for exclusion zones (§10).

---

## 8. Security tab
Seeded on open from `control.controlState()` (map): `vstdModeState=="1"` → Sentry armed; `visitorModeState=="1"`; `gloveboxLocked=="1"`.
| Row | Visibility | Behaviour |
|---|---|---|
| Sentry guard switch | all | optimistic flip → `control.send(SENTINEL_ON [rsm=6] / SENTINEL_OFF)`; revert on error (e.g. "lock the car first", #41). |
| Auto-enable Sentry on lock + trusted areas | all | §10.2 |
| Glovebox lock | owner only | switch opens PIN dialog (4–6 digits, numeric-password keyboard) → `GLOVEBOX_LOCK/UNLOCK [code=pin]`; state flips on confirm (optimistic). |
| Visitor mode | owner only | PIN dialog ("set PIN" when enabling, "enter PIN" when disabling) → `VISITOR_ON/OFF [code=pin]`. |
| Journey log | owner only | opens §6. |
| Car sharing | owner only | opens §13. |
Footer note: Send-to-car isn't a button — app is a share target (§12).
Sentry footage/live view: **hidden** (§14).

---

## 9. Parking (Remote Parking Assist, RPA) — DEV MODE ONLY, non-functional
Shown under the Location map only when `cfg.devMode`. Driven by `deps.rpa` (`RpaController`, BLE; covered by BLE doc).
- Phase pill: IDLE / CONNECTING / READY / ACTIVE (MOVING|PARKING_IN|PARKING_OUT) / PAUSED / DONE / ERROR; message line.
- Connect `rpa.begin()` (enabled in IDLE/ERROR/DONE), Stop `rpa.stop()`.
- Park-in: Search `searchSlot()`, Park in `startParkIn()`, Continue `continueParking()`, Pause `pause()`, Undo `undo()`.
- Park-out chips: `startParkOut(RpaReq.{PARALLEL_RIGHT_OUT, PARALLEL_LEFT_OUT, HEAD_PERPENDICULAR_RIGHT_OUT, HEAD_PERPENDICULAR_LEFT_OUT, TAIL_PERPENDICULAR_RIGHT_OUT, TAIL_PERPENDICULAR_LEFT_OUT})`.
- Hold-to-move pads (dead-man): press → `holdMove(forward)`, release → `releaseMove()`.
Status: every request NAK'd `0x100a` at the car (needs DK 3.0 / Secure Element). README: "closed" for the project.
Also a DEV probe on Key tab ("Probe RPA") → `lock.probeRpaStart()` with reply in snackbar (only when session ready).

---

## 10. Digital key, proximity, trusted areas (Key tab = SetupScreen)

### 10.1 Key card
- Provisioned & not busy: "Key active (offline) · DK ••••XXXX" + **Re-provision** (`provisioning.provision(owner)`) + **Remove key** (confirm dialog → `provisioning.removeKey()` (cloud revoke; keeps key if revoke fails, 0.2.6) + `PhoneKeyPush.purgeWatches()`).
- Not provisioned: stepper rows Enrol certificate (CERT) → Bind (BIND) → Key list (KEY_LIST) → Key info (KEY_INFO); owner/shared note; provision button.
- **At the car** card (when provisioned): connection state Connected / Connecting / Error(lastError) / Not connected; round button toggles `ble.disconnect()` / `connect()` (requests BLUETOOTH_SCAN+CONNECT on S+, else FINE_LOCATION; on grant `resetHandshakeBackoff()` + `connect(null, diagnostic=true)`).

### 10.2 Passive entry (approach unlock / walk-away lock)
- Master switch `proximityEnabled` — **enabled only once calibrated** (`isProximityCalibrated`); reads off until then.
- **Calibration walk** (bottom sheet): requires live session (else connect + "try again" snackbar). `calibTest.runCalibration()` 4-position walk (door → driver's side → ~6 m …); shows step x/N, measuring state, message; Cancel `calibTest.cancel()`. Saves `calibNearRssi`/`calibFarRssi` (shown "Calibrated: door −xx dBm, 6 m −yy dBm"). Recalibrate / Reset (`config.clearProximityCalibration()`).
- When enabled: independent toggles **Unlock on approach** (`autoUnlockOnApproach`, default true) and **Lock on walk-away** (`autoLockOnWalkAway`, default true).
- **Proximity exclusion zones** (`proximityExclusionZones`) — §10.3; apply whenever approach/walk-away is on (no master switch). Only gate the app's own actions, not car-side passive entry.
- **Approach sensitivity** chips very close / close / far (`proximitySensitivity`, default "close") + description; **Lock distance** chips (`lockSensitivity`, default close) — kept non-overlapping with unlock (#44).
- **Car-side passive entry (DEV only)**: toggles → `config.setPassiveEntry(a, w)` + `calibTest.setApproachUnlock/WalkAwayLock`; seeded from `provisioning.passiveState()`; warning that the car runs it everywhere (zones can't gate it).
- Runtime behaviour (implemented in `core/ble`, reference only): unlock ≥ −65 dBm default, lock ≤ −85 (README) / config default −70; EMA α=0.4; 8 s signal-loss walk-away; hardware-offloaded presence scan screen-off; motion gating; walk-away lock verified via `cloudLockState` with door-open alert + auto-lock-when-closed; cloud lock fallback; exclusion-zone check phone-first.

### 10.3 Geofenced zones (shared UI for Sentry trusted areas and proximity exclusion zones; two independent lists)
- "Add current location": needs FINE/COARSE (requests if missing) → `sentryAutoArm.currentLocation()` → name+radius dialog (radius digits only, ≤5 chars, default 150 m, must be > 0; name required) → `config.addSentryExclusionZone` / `addProximityExclusionZone(GeoZone(name, lat, lng, radiusMeters))`.
- "Add on map": full-screen `ZonePickerMap` dialog, start at current location if permitted, radius slider 50–500 m (default 150), name required.
- List rows: name + "lat, lng (4 dp) · r m" + delete (`remove…Zone`).
- Sentry auto-arm (`autoSentryOnLock`): on lock event, if enabled & VIN set: get phone location; **no fix → do NOT arm (fail-closed)**; inside any Sentry zone → skip; else `SENTINEL_ON`. Sentry zones never affect proximity (0.2.7 fix).

### 10.4 Force unlock toggle (lock-screen volume gesture) — see §11
Switch `forceUnlockKeyCombo`; enabled only when `KeyguardManager.isDeviceSecure`; turning on requires a warning dialog (anyone holding the locked phone who knows the gesture can open the car).

---

## 11. Force-unlock over keyguard (`forceunlock/`)
- `ForceUnlockManager.init(app)`: runtime receiver for `ACTION_SCREEN_ON` (can't be manifest-declared; survives because the BLE FGS keeps the process alive). Own channel `force_unlock_combo` ("Force unlock", IMPORTANCE_HIGH, no badge).
- On each screen-on gate: flag on → device secure → device **locked** → audio mode not RINGTONE/IN_CALL/IN_COMMUNICATION (don't hijack a call wake, 0.2.4 fix). Then post a full-screen-intent notification (CATEGORY_ALARM, timeout 4 s, auto-cancel) targeting `ForceUnlockActivity` (Android 14+: needs `canUseFullScreenIntent()` grant, degrades to heads-up).
- `ForceUnlockActivity` (not exported, showWhenLocked, does not turn screen on, noHistory, excludeFromRecents, translucent): re-checks flag + locked; UI with gesture hint + "Unlock phone" (`requestDismissKeyguard`). Listen window **4 s**; closes on `USER_PRESENT`, `SCREEN_OFF`, timeout, or lock-state poll (300 ms, catches face unlock).
- Gestures: double-press (≤500 ms, same key, auto-repeat ignored, other key resets) **Vol Up → unlock**, **Vol Down → lock**; volume key events swallowed. Hard safety: never actuate unless still locked.
- Actuation on `deps.appScope` under 30 s partial wakelock: require `ble.hasCredential`; `resetHandshakeBackoff()`; if not SESSION_READY → `ble.connect(null)` and wait ≤15 s; then `lock.unlock()` / `lock.lock()` (BLE only, no cloud fallback). Feedback "Unlocking/Locking the car…" for 1.2 s, then finish.
- Strings here are hard-coded English (not localized).

---

## 12. SendToCar (geo / share intents)
`SendToCarActivity`: exported, translucent, no history, label "Send to Zeekr". Intent filters: `VIEW geo:` (DEFAULT+BROWSABLE), `VIEW google.navigation:`, `SEND text/plain` (Google Maps "Share").
Flow: parse on IO → if null toast "Couldn't read location from: <first 48 chars>" and finish → else **always confirm** dialog "Send “name” to the car's navigation?" (activity is exported; prevents silent POI injection) → `deps.nav.sendToCar(lat, lon, name, address, city)` on appScope → toast "Sent to Zeekr ✓" / "Send failed: msg".
Parsing (`parseDestination`):
1. Collect blobs: URI `q` and `destination` params, scheme-specific part, dataString, EXTRA_TEXT, EXTRA_SUBJECT, ClipData items. Explode into whole blobs + lines + whitespace tokens (distinct).
2. Coordinates in any candidate (also URL-decoded copy). Regex priority: `[!/]3d<lat>[!/]4d<lon>`, `@lat,lon`, `[?&](q|ll|sll|daddr|destination|center)=lat,lon`, generic `lat,lon` with ≥2 decimals. Valid range, not (0,0).
3. Else a Google Maps link (goo.gl / google. / maps.) → follow up to 6 redirects manually (6 s timeouts, mobile UA), scan URL chain + first 40 kB of body. **SSRF guard**: only http/https whose host resolves entirely to public addresses (no loopback/site-local/link-local/any/multicast/169.254.169.254) — checked on every hop.
4. Else geocode first plain address-like line (`Geocoder.getFromLocationName`) → name/address/city.
Label: `(Label)` parenthetical, else first non-URL non-coord line 2–80 chars, else "Destination". Coordinates sent raw WGS-84 (server converts). Strings not localized.

---

## 13. Car sharing
**Owner side** (Security → Car sharing; owner only): `share.myShares()` list; card = name (or contact), contact if different, granted functions, "Until <date>" only when end/expire is in the FUTURE (permanent DK shares return a stale past `expireTime`). Revoke (confirm) → `share.revoke(grant)` → reload. Share (person-add icon): email dialog, enabled when trimmed contains '@' and length ≥ 3 → `share.createShare(email)` → reload; invitee accepts in their Zeekr app (or OpenZeekr).
**Recipient side**: invite dialog in AppRoot (§0.5); manual "Check for shared cars" in Settings (`refreshInvites()` → "Found n invitation(s)" / "No invitations").
Shared accounts: Updates tab hidden; owner-only rows hidden; digital key uses shared-key provisioning path (`provision(owner=false)`).

---

## 14. Sentry (camera feeds) — hidden
`SentryScreen` exists but is not reachable (Tab enum omits it). Functions: list events last 24 h (`sentry.events(start,end)`), download clip (`sentry.prepareDownload(id, start, end)` → `DownloadManager` enqueue), live view token (`sentry.liveToken(vin)`). Backend `sentinel-monitoring-service` returns 404 `00A01` on all overseas gateways → **broken / CN-only**. Only Sentry arm/disarm (RSM) works (Security tab, widget).

---

## 15. Inbox / notifications

### 15.1 Inbox screen (bell in top bar)
Requires overseas credentials (`overseas_access_key/secret_key`); without them calls fail softly.
- Load `inbox.messages(page=1)` (30 per page) + `inbox.unreadCount()` (authoritative unread from `/home`, since unread can sit on deeper pages).
- Row: category icon/colour (keyword heuristic on category+title: charging/battery → bolt amber; alarm/sentry/theft/abnormal/park/security → shield red; ota/update/firmware → update; vehicle/lock/door/climate/window/control → car; else bell), title, unread dot, body preview, relative time (just now / Nm / Nh / Nd (<7) / "d MMM").
- Tap: optimistically mark read + `inbox.markRead(id)`; open **in-app** detail dialog (title, body or "no details"). "Open link" only for http/https `redirectUrl` (never auto-follows `zeekr://` / `zeekr-overseas://` deep links, which would open the stock app).
- "Mark all read" shown when serverUnread > 0 or any unread loaded → `inbox.markAllRead()` (marks every unread across all pages/categories) → snackbar + reload.
- Back closes detail first, then screen.
- Unread badge in AppRoot refreshed on login and on closing inbox.

### 15.2 Notification channels
| Channel id | Name | Source / importance |
|---|---|---|
| `car_charging` | Charging & battery | CarNotifier, seeded from legacy `car_alerts` settings, default HIGH |
| `car_security` | Security & parking | also walk-away lock alerts (`LOCK_ALERT_ID = 0x10C7`, ongoing while unresolved) |
| `car_vehicle` | Vehicle controls | |
| `car_updates` | Software updates | |
| `car_service` | Service reminders | |
| `car_news` | News & offers | |
| `car_alerts` | Car alerts (uncategorised) | fallback + FCM `default_notification_channel_id` (manifest meta-data) |
| `proximity` | Digital key | ProximityService ongoing FGS notification, IMPORTANCE_LOW ("OpenZeekr digital key active / Keeping your key connected…") |
| `force_unlock_combo` | Force unlock | full-screen-intent launcher, HIGH |
`CarNotifier.ensureChannels`: new channels inherit importance/sound/vibration/lights/badge from the legacy `car_alerts` channel (can't copy lock-screen/DND overrides); names re-localized once per process.
`CarNotifier.notify(msg)`: title (or "Zeekr"), BigText body, CATEGORY_MESSAGE, HIGH, auto-cancel; tap → launcher intent with `EXTRA_DEEP_LINK = redirectUrl` (**currently never read by MainActivity** — tap just opens the app). Notification id = hash(id or "title:time"). No-ops if POST_NOTIFICATIONS denied.
`CarNotifier.notifyAlert(category, title, text, id, ongoing)`: app-generated alerts; `setOnlyAlertOnce`; `cancelAlert(id)`.

### 15.3 Category classifier (`CarNotificationCategory.forMessage`)
1. Normalize hints (`categoryHints` + `category`): split camelCase/acronyms, lowercase, non-alnum → space.
2. Exact backend group hints first: `ota` → UPDATES, `after sales` → SERVICE, `zeekr` → NEWS.
3. Other hints: charging/charge/battery → CHARGING; security → SECURITY; updates/software updates → UPDATES; service/maintenance → SERVICE; news/marketing → NEWS; else classify hint as title.
4. Title classification (whole-word regex, in order): news (newsletter|promotion|discount|offer|zeekr news) → NEWS; update (ota|firmware|software update/upgrade) → UPDATES; service (service reminder/due/appointment|maintenance|servicing) → SERVICE; (security words AND alert words) OR parking words ((car|vehicle) (is being)? towed | abnormal parking) → SECURITY; charging (char?g(e|er|ing)|batter(y|ies)|state of charge; tolerates "Chaging") → CHARGING; vehicle words (remote control|climate|air conditioning|door(s)|window(s)|lock(ed)|unlock(ed)|trunk|frunk) → VEHICLE; else OTHER.
Never classifies on body/URL text. Unit-tested in `core/src/test/.../CarNotificationCategoryTest.kt`.

### 15.4 Push (FCM) — `ZeekrFcmService`
Uses the **stock Firebase project** via gitignored `core/res/values/secrets_firebase.xml` (absent → push disabled). Token registered with the message-centre by `PushRegistrar.registerIfLoggedIn()` (called from AppBootstrap), `onNewToken` re-registers (process-lifetime scope), `disableOnLogout()` on sign-out.
`onMessageReceived`:
- Parse `data["url"]` deep link (`zeekr-overseas://…?title=&content=&showBanner=&data=…`) query params.
- If URL contains `OTAAssignmentStatusUpdate`: parse `data` JSON (`vin, status, reason, scheduledTime`) → `OtaStatusBus.emit(...)` (no replay, buffer 16) — then falls through (usually silent).
- Title: notification.title → data.title → q.title → "Zeekr". Body: notification.body → data.content/body/desc → q.content.
- Notify iff notification payload present, OR showBanner=true, OR (showBanner absent AND has real text). Silent remote-control progress pushes (TRS/RSM/RCS) are dropped.
- `CarNotifier.notify(InboxMessage(id = messageId|msgId|url|…, category = data.bizType, redirectUrl = url, categoryHints = [bizType, category, type, groupType] from data+query))`.
Background notification-payload pushes are auto-displayed by the SDK on `car_alerts` (cannot be classified; muting it may silence alarms).
Fallback: `ProximityService` polls `inbox.messages()` every **5 min** (when `overseasReady`), seeds a persisted "last seen" timestamp on first run, then posts every newer unread message.

---

## 16. Car catalog, hero renders, 3D animation

### 16.1 `CarCatalog` — supported models & paints
Resolve model from vehicle-list modelName/seriesName/innerCode (uppercased, spaces removed): contains "7GT"/"007GT" → 7GT; "CX1E"/"7X" → 7X; "9X" → 9X; "001" → 001; == "X" or contains "ZEEKRX" → X; **default 7GT**.
| Key | Display | Paints (name, hex, finish) | Assets |
|---|---|---|---|
| 001 | Zeekr 001 | Crystal White DEDEDE Pearl; Tech Grey 3B3B3E; Phantom Black 2B2B2B; Electric Blue 35AACB; Energy Orange FF7F00; Forest Green 2E3B2E; Mineral Green 5A6B5A; Lava Grey 6E6F72 (Metallic) | `cars/car_001.webp` |
| X | Zeekr X | Crystal White F3F6FA Pearl; Mist Grey 9A9CA0; Grid Grey 65666A; Palace Beige E0D2AF; Pine Green 3C4A32 (Metallic); Matt Khaki Green 909602 Matte | `cars/car_x.webp` |
| 7X | Zeekr 7X | Forest Green 436238; Crystal White BDC0C3 Pearl; Onyx Black 111111; Tech Grey 868686; Brookblue 677FA3 Two-tone; "Shadow Blue (including silver roof)" 677FA3 Two-tone (AU name) | `car_7x.webp`, `7x_body.png` + `7x_details.png`, hero3d pack `7x` |
| 7GT | Zeekr 7GT | Mystic Lilac B9A7C4 Pearl; Crystal White F0F1F3 Pearl; Glacier Silver CED3D9; Tech Grey 84878B; Titanium Grey 524E54; Onyx Black 1C1D20; Forest Green 2B4437 (each with calibrated RGB recolour scale) | `car_7gt.webp`, `7gt_body/details.png`, hero3d pack `7gt` |
| 9X | Zeekr 9X | Onyx Black 1A1A1A; Crystal White EDEFF2 Pearl; Lava Grey 6C6E71; Glacier Silver C6CACE; Wilderness Green 4A5648 | `car_9x.webp` |
Colour matching (`colorFor`): exact normalized (lowercase, strip spaces/-/_ and finish words) → token overlap (≥3-char tokens / ≥4-char palette tokens) → localized aliases (noir/schwarz/negro/nero/onyx→black; blanc/weiss/blanco/bianco/crystal→white; gris/grau/gray/grigio/tech→grey; vert/grün/verde/forest→green; bleu/blau/azul→blue; silber/argent→silver) → **no match: keep reported name, neutral graphite #6E7075** (never a wrong vivid paint, issue #8). Null/blank → neutral.
Renders are Zeekr press images: **gitignored** (`app/src/main/assets/cars/`); app works without them (coloured card only).
(Wear and AA energy profiles list more variants: 001 RWD/AWD/FR, 7GT AWD/RWD 100/RWD 75, 7X, 009 116/140, X — AA routing only.)

### 16.2 Animated hero (`Hero3d`, 0.2.9; 7GT + 7X)
- Asset pack `assets/cars/hero3d/<key>/manifest.json` (gitignored). Presence check = manifest exists. Layers pre-rendered offline from a fixed camera looking at the car's **right-hand side**; paint-affected layers ship twice (near-white W and black K); any paint = K + tint·(W−K) in linear light, computed once per colour at load (manifest: canvas, steps, car_x, part_order, parts, glass, wheels[frames, smear], wheel_radius, shadow, body, lights, neon_lines, neon_glow, w_albedo, curve{black,gamma}; null frames = invisible poses, `hidden_parts`).
- `Hero3dStatus`: doorNearFront/Rear, doorFarFront/Rear, hood, tailgate, window 0..1 (vent 0.25, open 1), speedKmh, charging, soc.
- Near/far mapping uses steering side: `VehicleInfo.rightHandDrive` else `countryCode ∈ RHD_COUNTRIES` (AU, NZ, GB, UK, IE, MT, CY, HK, MO, SG, MY, TH, ID, BN, JP, IN, PK, BD, LK, NP, ZA, KE, TZ, UG, ZM, ZW, BW, NA, MZ, MU, JM, TT, BB, BS, FJ, PG). RHD: near = driver side.
- Animations: doors 900 ms, hood 1100, tailgate 1300, window 1400 (linear); wheels spin at true speed via wheel radius (capped to avoid strobing), motion smear 12→40 km/h; headlight flash 110/190 ms; charging glow covers SOC fraction from rear with sweep (1.9 s) and pulse (1.3 s).
- `Hero3dFx.onCommand(cmd)` gives instant optimistic feedback for 15 s (then car status wins): FLASH/FLASH_HORN → flash; FRONT_TRUNK → hood 1; TRUNK_OPEN/UNLOCK → tailgate 1; TRUNK_LOCK → 0; WINDOW_OPEN 1 / VENT 0.25 / CLOSE 0.
- Driving → speed badge top-right.
- **Hero Lab** (DEV, Settings → App): sandbox rendering the two-layer hero in Still/Charging/Driving modes with model & paint switchers.

---

## 17. Wear OS phone-side (`wear/PhoneKeySyncService`, `PhoneKeyPush`)
`PhoneKeySyncService` (WearableListenerService, MESSAGE_RECEIVED on `wear://*/openzeekr/*`). Paths (`WearKeyProtocol`, in :core):
- `PATH_REQUEST` → send `PATH_KEY` with `DkIdentity.exportCredentialBlob()` JSON (or `{}`). Transient message, never a DataItem.
- `PATH_STATUS_QUERY` → `PATH_STATUS` `{"connected": "1"/"0" (BLE CONNECTED/SESSION_READY and not suspended), "prox": "1"/"0"}`.
- `PATH_PAUSE` → `WearLinkArbiter.suspendForWatch()` (phone releases its single BLE slot), ack; `PATH_RESUME` → `WearLinkArbiter.resume()`.
- `PATH_SNAPSHOT_QUERY` → `PATH_SNAPSHOT` `WearVehicleSnapshot{cloudOnline, locked, soc, rangeKm, charging, pluggedIn, portOpen, chargeKw, acOn, insideTempC, updatedAt}` (fetch status once if none cached).
- `PATH_CONTROL` body `"<CONTROL>[|arg]"` → map `WearControl`: CLIMATE_ON(arg °C, default 22) → `CLIMATE_ZAF [AC=true, AC.temp, AC.duration=15]`; CLIMATE_OFF → AC_OFF; CHARGE_START/STOP → CHARGING_ON/OFF; CHARGE_PORT_OPEN/CLOSE → CHARGE_LID_OPEN/CLOSE; FLASH_HORN. Run via `vehicleControl.send`, reply `PATH_CONTROL_ACK` `"<NAME>|ok"` / `"<NAME>|err|msg"`, then `refreshAfterCommand()`, wait 1.5 s, push snapshot.
`PhoneKeyPush.pushToWatches()` (on provisioning DONE) / `purgeWatches()` (`PATH_PURGE` on remove key / sign-out). README warning: watch holds a working key; revoke from phone.

---

## 18. Update checker (app self-update)
`UpdateChecker.fetchLatest()` → `https://api.github.com/repos/borconi/openzeekr/releases/latest` → `ReleaseInfo{version, url, notes}`; `isNewer(installed, latest)` compares dotted ints (strips leading v and `-`/`+` suffix).
- Auto check once at Deps creation. AppRoot dialog "Update available: X (installed Y)" with first 8 non-blank lines of notes; Download → open `rel.url` in browser; Download or Later persists `oz_update/dismissed_version` → prompt once per version (re-prompts for newer).
- Settings About: "Update available — download X" row (when available) + "Check for updates" button → `deps.checkForUpdate()` → "Found X" / "You're on the latest".
- No in-app installer; APK is sideloaded from GitHub releases.

---

## 19. Android Auto tab (reference; `:aa` covered elsewhere)
Prefs file `AA_SETTINGS` (keys byte-identical to the ported original): `aa_enabled` (master, default false), `offset_value` (cluster range offset −10..10), `replace_maps` (default true, show Waze police HUD in place of cluster secondary map), `waze_api_key`, `waze_interval_sec` (default 300, min 15), `energy_profile` (default `zeekr_7gt`), `camera_sources` (newline list of GitHub `owner/repo`, default `1e1/Open-GATSO-POI` (EU+Canada) and `apgneto/br-open-speedcameras` (Brazil); add validated via `GatsoUpdater.isValidRepo`, dedup, remove, reset-to-defaults).
Behaviour: Android 13+ only (notice below); enabling triggers `AaCertMaintenance.maintain`; cert card shown only on `EXTRACTION_FAILED`; setup steps (dev settings, disable wireless AA, start Head unit server) with doc links; Waze key test; energy-profile picker (EV routing in Maps). Bootstraps only when car Bluetooth connects and head unit is a Zeekr.
"Camera feeds" (0.2.9) = these speed-camera / red-light feed sources.

---

## 20. Settings tab

### 20.1 Content
- **Profile**: avatar initial, email or "Not signed in", "ID xxx · VIN …1234".
  - Logged out: email/password `LoginField`s + Sign in → persist only email (trimmed)/password onto LIVE config (never the stale snapshot — fix #77 region revert) → `auth.login()` → status text.
  - Logged in: **Check for shared cars**; **Sign out** (confirm: wipes account + key and revokes it) → `provisioning.removeKey()` → `PhoneKeyPush.purgeWatches()` → `push.disableOnLogout()` → `config.signOut()` (clears credentials, tokens, ids, VIN, vehicles, nickname, device ids, both zone lists, BLE MAC, auto-Sentry, proximity) → `onEndpointChanged()`.
- **Units**: Distance km/mi (`distanceUnit`), Tyre pressure bar/psi/kPa (`pressureUnit`), Temperature °C/°F (`tempUnit`). Applied live (`config.update`). **Gap**: `tempUnit` is stored but no screen uses it (climate/fridge always °C).
- **Region**: same chips as onboarding (`setRegion` + rebuild). Advanced (expand): TSP gateway `baseUrl`, Azure host, xchanger host, projectId, country code, SNS region — each edit written live; baseUrl/projectId also rebuild client. Note: switching region resets these.
  Region catalog (`net/Region.kt`): EU "Europe (EU)" verified (defaults `https://eu-snc-tsp-api-gw.zeekrlife.com`, project `ZEEKR_EU`, country SE, Azure `https://gateway-pub-azure.zeekr.eu`, xchanger `https://api-zk.ecloudeu.com`, SNS eu-central-1); SEA "Australia + SEA" unverified; LA "Latin America (LA/BR)" `verified = true` in code (tested on a 7X in Brazil, 0.2.5) though README still calls non-EU experimental; ME "Middle East" unverified. Country follows the account after login.
- **App**:
  - **HTTP logging** / **BLE logging** switches (`logHttp`, `logBle`; default off). Turning ON shows a sensitive-data warning (key material, tokens, VIN, device ids, location; password never logged); OFF is immediate. `Logx` categories: HTTP tags {http, login, net, session, tsp, push, status, fcm}; BLE tags {ble, carprox, dk, lock, motion, provision, prox, svc, ctl}. Warnings/errors always buffered. Ring buffer 5000 lines `HH:mm:ss.SSS L/area msg`; cleared when both off. `Logx.preview(secret)` shows only length + last 4.
  - **Log viewer** (when any logging on): live lines + **Share** (encrypted file, §20.3), **Copy** (encrypted to clipboard; refuse if blob > 200 000 chars; warn if > 19 000 chars that paste targets may truncate), **Clear**.
  - **Hero lab** (DEV).
  - **Ping vehicle**: `ble.session.ping(2000)` → "reply (command link alive)" / "no reply" (needs live session).
  - **CCC / Apple Wallet pairing probe**: `provisioning.fetchCccPairingCode()` → builds `https://wallet.apple.com/setup/carkey-pairing?brand=ZKR1&supportedRadioTechnologies=BT,NFC#<pw>` (and a UWB variant) and copies the BT,NFC URL with `SensitiveClipboard` (never logged).
- **Secrets** (only non-baked builds; collapsed): fields hmac access/secret, password public key, prod secret, vin key/iv (16-byte hint/error), xchanger sign secret, overseas access/secret (both-or-neither error), VIN; Save overlays only these fields onto live config via `config.replace(...)` (validates via `check()`) → `onEndpointChanged()`.
- **Import / Export** (non-baked): paste JSON → `importJson`; Export → confirm dialog (plaintext secrets warning) → `SensitiveClipboard.copy(exportJson(includeAccountCredentials))`; "include password & tokens" checkbox default off.
- **About**: Version (tap **10×** toggles developer mode: hint after 6 taps; when on, a row "Developer mode — tap to turn off"), Build "private (baked)" vs "clean", update row/button, blurb, credits (Wysie, Fryyyyy, mescon), donate link (Revolut).
Developer mode (`devMode`) unlocks: Hero lab, Remote parking controls, car-side passive entry, AC charge current, OTA "Cancel update", (RPA probe shows whenever session ready).

### 20.2 Startup housekeeping (`AppBootstrap`, once per process)
- Request foreground permissions: FINE + COARSE location; S+: BLUETOOTH_SCAN, BLUETOOTH_CONNECT, BLUETOOTH_ADVERTISE; T+: POST_NOTIFICATIONS; Q+: ACTIVITY_RECOGNITION. Then (Q+, after FINE granted) ACCESS_BACKGROUND_LOCATION separately.
- Prompt `ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` if not exempt.
- `push.registerIfLoggedIn()`.
- Keep `ProximityService` running exactly while logged in + provisioned and (S+) BLUETOOTH_CONNECT granted; stop when not eligible.

### 20.3 Encrypted log share + `decrypt_log.py`
- `LogCrypto.encryptToBase64(Logx.dump())`: random AES-256 key + 12-byte IV, AES-256-GCM (128-bit tag appended), key wrapped with embedded **RSA-4096 public key** using OAEP SHA-256 / MGF1-SHA-256. Blob = `"OZ" | version 1 | wrappedKeyLen (2 B BE) | wrappedKey | IV(12) | ct+tag`, base64 NO_WRAP. Returns null on any failure → **never fall back to plaintext**.
- `shareEncryptedLog(ctx)`: write `cacheDir/exports/openzeekr-log-yyyyMMdd-HHmmss.txt`, share via FileProvider (`ACTION_SEND text/plain`, subject/body localized, chooser, NEW_TASK). Available from Settings log viewer and onboarding login failure.
- `scripts/decrypt_log.py --key tools/log-decrypt/private_key.pem [--in file | stdin | arg]` (needs `cryptography`): validates magic/version, unwraps key, AES-GCM decrypt; with allow-truncated mode recovers truncated blobs unauthenticated via AES-CTR from counter IV‖00000002 (warns). Private key gitignored, kept offline; rotation via openssl commands in `scripts/README.md` and paste DER base64 into `PUBLIC_KEY_B64`.
- `SensitiveClipboard.copy`: sets `android.content.extra.IS_SENSITIVE` (hidden from clipboard preview/keyboard history on 13+).

---

## 21. Home-screen widget (`widget/QuickActionWidget`, Jetpack Glance)
- Receiver `QuickActionWidgetReceiver` (not exported). Provider: min 110×60 dp, target 4×2 cells, resizable both axes to 320×300 dp, home_screen, preview drawable. `SizeMode.Exact`.
- State per widget (Glance Preferences): `oz_widget_status` (status line), `oz_widget_locked` (last widget-driven lock), `oz_widget_sentry` (last widget-driven Sentry).
- Header: status dot (green when `accessToken` & `vin` set, else amber), car nickname (wide only), status line (last result, or "Ready" / "Open app to sign in").
- Tiles: Lock/Unlock toggle (state = cached widget state else live `centralLockingStatus=="1"`, null → offers Lock), Trunk (`TRUNK_UNLOCK`), Charge port (`CHARGE_LID_OPEN`), Flash+honk (`FLASH_HORN`), Sentry toggle (cached, default off → `SENTINEL_ON`, else `SENTINEL_OFF`).
- Layout by actual size: width ≥ 275 dp → all 5 in one row; width ≥ 190 & height ≥ 90 → rows (Lock, Trunk, Charge) + (Flash, Sentry); width ≥ 190 → Lock, Trunk, Charge, Sentry; else Lock, Trunk. Signed-out tiles dimmed but tappable.
- `CommandActionCallback`: no Deps → error status; not signed in → "Open app to sign in"; else status "label…" → `withTimeout(9 s) { vehicleControl.send(cmd) }` → "label ✓" / error; error containing `088028` (car offline / queue full) → "Car offline — move closer or wake it". On success update cached lock/Sentry. Re-render widget.
- Colours pinned (dark) regardless of launcher theme.

---

## 22. i18n
- Default English `values/strings.xml` (~864 strings) + 27 locale folders: ar, bg, cs, da, de, el, es, es-rMX, et, fi, fr, ga, hr, hu, it, lt, lv, mt, nb, nl, pl, pt, pt-rBR, ro, sk, sl, sv (CHANGELOG counts "27 languages" incl. English). Follows system locale; no in-app language picker, no `localeConfig`. Fallback English (incl. Ireland/Malta).
- RTL: `android:supportsRtl="true"`; Arabic lays out RTL; back arrows use `Icons.AutoMirrored`.
- Some strings marked `tools:ignore="MissingTranslation"` (newer ones, e.g. auth banner, export confirm).
- Not localized (hard-coded English): ForceUnlockActivity/Manager texts, SendToCarActivity dialog/toasts, CarCatalog paint/model names, `Command.title`, notification fallback "Zeekr".
- Norwegian wording fix ("avgang") in 0.2.8.

---

## 23. Android manifest: permissions, components

### 23.1 Permissions (declared in `core/src/main/AndroidManifest.xml`, merged)
| Permission | Why |
|---|---|
| INTERNET, ACCESS_NETWORK_STATE | cloud TSP/Azure/xchanger, GitHub update check, map tiles, FCM, URL expansion |
| FOREGROUND_SERVICE, FOREGROUND_SERVICE_CONNECTED_DEVICE | `ProximityService` keeps DK BLE session alive (type connectedDevice) |
| POST_NOTIFICATIONS | car messages, FGS notification, lock alerts |
| USE_FULL_SCREEN_INTENT | force-unlock panel over keyguard (Android 14 user grant) |
| REQUEST_IGNORE_BATTERY_OPTIMIZATIONS | startup prompt so background BLE/proximity isn't killed |
| WAKE_LOCK | keep CPU awake while ProximityService scans screen-off; force-unlock actuation |
| BLUETOOTH_SCAN, BLUETOOTH_CONNECT, BLUETOOTH_ADVERTISE (+ legacy BLUETOOTH/ADMIN maxSdk 30) | DK GATT, RSSI ranging (no `neverForLocation`), in-cabin positioning beacon (calibration / passive entry) |
| ACCESS_FINE/COARSE_LOCATION, ACCESS_BACKGROUND_LOCATION | BLE scan on older APIs, RSSI/MAC ranging, geofenced zones (Sentry/proximity), background proximity |
| ACTIVITY_RECOGNITION (+ GMS variant) | motion fallback for proximity cadence on phones without hardware motion sensors |
| uses-feature `bluetooth_le` required=true | |
| `<attribution tag="proximity">` | AppOps attribution for continuous BLE + motion |
Plus transitively: Wear Data Layer (play-services-wearable), Firebase Messaging.

### 23.2 Components
| Component | Exported | Notes |
|---|---|---|
| `MainActivity` | yes (launcher) | single Compose activity |
| `SendToCarActivity` | yes | geo:/google.navigation:/SEND text/plain; translucent, noHistory, own taskAffinity |
| `forceunlock.ForceUnlockActivity` | no | showWhenLocked, turnScreenOn=false |
| `FileProvider` `${applicationId}.fileprovider` | no (grantUriPermissions) | `res/xml/file_paths.xml`: `cache-path exports/` (CSV + logs) |
| `wear.PhoneKeySyncService` | yes (Wearable listener, path prefix `/openzeekr/`) | |
| `push.ZeekrFcmService` | no | `MESSAGING_EVENT`; meta-data default channel `car_alerts` |
| `widget.QuickActionWidgetReceiver` | no | `APPWIDGET_UPDATE`; `res/xml/quick_action_widget_info.xml` |
| `ble.ProximityService` (core) | no | FGS connectedDevice; also 5-min inbox poll |
| `ble.BleScanReceiver` (core) | no | hardware-offloaded presence scan PendingIntent (FIRST_MATCH/MATCH_LOST) |
| `ble.ActivityRecognitionReceiver` (core) | no | activity transitions → MotionMonitor |
| runtime receivers | — | `ACTION_SCREEN_ON` (ForceUnlockManager), `USER_PRESENT`/`SCREEN_OFF` (ForceUnlockActivity); `:aa` has its own BT receiver/service |
`application`: `allowBackup=false`, `supportsRtl=true`, theme `Theme.OpenZeekr`.

### 23.3 Local persistence summary
| Store | Contents |
|---|---|
| `EncryptedSharedPreferences` `openzeekr_secure_config/config_json` | whole `SecretsConfig` JSON (secrets, credentials, tokens, region/hosts, vehicles, proximity/calibration, zones, toggles, units, devMode, onboarding flags, chargeLimitPct, nickname) |
| `climate_prefs` | `target_temp_c` (22), `fridge_temp_c` (5), `fridge_on` (false) |
| `oz_update` | `dismissed_version` |
| `AA_SETTINGS` | AA feature settings (§19) |
| Glance prefs | widget status/lock/Sentry |
| ProximityService prefs | inbox last-seen timestamp |
| DkIdentity store (core) | device id, DK keypair/credential, pins |

---

## 24. Build & release
- Gradle: AGP 8.7.2, Kotlin 2.1.0 (+ compose & serialization plugins), protobuf plugin 0.9.6 (`:aa`). JDK 17 (full JDK with `jlink`), compileSdk 35, targetSdk 34, minSdk 26. NDK `27.0.12077973` (in `gradle.properties` `openzeekr.ndkVersion`), CMake 3.22.1 for `libozsecrets.so`.
- `settings.gradle.kts` preflight: fails early on Java < 17, missing jlink, missing SDK (local.properties `sdk.dir` / ANDROID_HOME / ANDROID_SDK_ROOT); warns on missing NDK.
- App deps: Compose BOM 2025.06.01 (Compose 1.8 autofill), material3 + icons-extended, activity-compose 1.9.2, lifecycle 2.8.6, navigation-compose 2.8.1 (unused for routing), MapLibre 11.13.5, play-services-wearable 18.2.0, glance-appwidget 1.1.1. Core carries okhttp/retrofit/kotlinx-serialization/security-crypto/BouncyCastle via `api`.
- Secrets: optional gitignored `secrets.properties` (HMAC_ACCESS_KEY, HMAC_SECRET_KEY, PASSWORD_PUBLIC_KEY, PROD_SECRET, XCHANGER_SIGN_SECRET, OVERSEAS_ACCESS_KEY, OVERSEAS_SECRET_KEY, INBOX_AUTH_SECRET, VIN_KEY, VIN_IV, USER_ID, EMAIL, PASSWORD, VIN) → generated `core/src/main/cpp/secrets_generated.h` → native lib (obfuscation, not encryption); only PASSWORD_PUBLIC_KEY in BuildConfig. Absent → clean build, configure in app. Firebase: gitignored `core/src/main/res/values/secrets_firebase.xml` (absent → push off).
- Release: `isMinifyEnabled = true`, `isShrinkResources = true`, `proguard-rules.pro` (core ships NO consumer rules → all keep rules in app/ and wear/). Signing from gitignored `keystore.properties` (storeFile, storePassword, keyAlias, keyPassword, optional storeType PKCS12); absent → unsigned release. Same `applicationId` + signing key shared with `:wear` (required for Data Layer key cloning).
- Verification tasks: `./gradlew verify` = `verifyBuild` (assembleDebug all) + `verifyTest` (JVM unit tests) + `verifyLint` (lint with per-module `lint-baseline.xml`, errors fail, GradleDependency disabled) + `verifyRelease` (R8 release of app+wear). Trunk (`.trunk/`) for linters/formatters/secret scanning; `.editorconfig` is the ktlint/IDE contract. Unit tests live in `core/src/test` (notification categories, inbox metadata, charge power, VIN crypto, config export, signed-out config, DK CMAC, DK trust pin).
- Distribution: signed APK on GitHub Releases (`borconi/openzeekr`); in-app update checker points there. No CI workflow files present in this checkout.
- Gitignored assets: `app/src/main/assets/cars/`, `wear/src/main/assets/cars/` (press renders + hero3d packs).

---

## 25. Feature status matrix
Legend: ✅ working/verified · 🟡 built, unverified/partial · 🔴 broken/not available · ⚙️ dev-only.

| Feature | Status | Notes / source |
|---|---|---|
| Account login (idaas → TSP bearer) | ✅ EU; 🟡 SEA/ME; ✅ LA (0.2.5, tester) | README; region revert bug fixed 0.2.8 (#77) |
| Region selector + advanced host overrides | ✅ | |
| Secrets import / manual entry / export | ✅ | export excludes credentials by default (0.2.6) |
| Onboarding wizard | ✅ | |
| Vehicle status (lock/doors/SOC/range/climate/odometer/tyres/location) | ✅ EU | quirks: SOC in chargeLevel, charging from kW |
| Live speed / driving hero | ✅ | 0.1.9 |
| Lock / unlock (BLE DK) | ✅ verified at car | |
| Lock / unlock (cloud) | ✅ | |
| Unified BLE-first/cloud quick actions | ✅ | |
| Climate on/off + target temp | ✅ core | some commands state-gated |
| Rapid cool / heat | 🟡 | 0.2.4, uses A/C at 16/28 °C |
| Seat heat / ventilation (cooling) | ✅ | debounce fix 0.2.8; rear vent capability-gated |
| Steering-wheel heat, defrost, cabin ventilate | 🟡 | no reliable readback for wheel/vent |
| Windows open/vent/close, sunroof, sunshade | ✅/🟡 | sunroof/sunshade capability-gated |
| Trunk (open/unlatch/close), frunk | ✅ | one-tap since 0.2.7 |
| Flash / flash+horn | ✅ | no honk-only |
| Charge port open/close, start/stop charging | ✅ (state-gated) | |
| Charge limit | ✅ | rounding fix #46 |
| AC charge current | 🔴 on EU 7GT ⚙️ | car-side gate (acRange=0) |
| Battery pre-conditioning | 🟡 | |
| Fridge on/off + temp | ✅ | persistence fix #79 |
| Off-peak charging schedule | 🟡 | car must be awake |
| Departure plans | 🟡→✅ | "too close" fix #36 |
| Journey log + record switch + CSV export | ✅ (owner only) | trail service 504s; date range #39 |
| Location map + navigate to car | ✅ | live follow 0.2.3 |
| Send to car (geo/share) | ✅ (README not listed; implemented) | confirm dialog + SSRF guard |
| Sentry arm/disarm | ✅ | requires locked (#41) |
| Auto-Sentry on walk-away lock + trusted areas | 🟡 experimental | fail-closed without location |
| Auto-Sentry on manual lock | 🔴 not wired in live UI | only in dead ControlsScreen |
| Sentry footage / live view | 🔴 CN-only (404 00A01) | hidden |
| Glovebox PIN / visitor mode | 🟡 (owner only) | |
| Car sharing: list / revoke / share by email | ✅ (0.2.4) | |
| Accept shared-car invitations in app | ✅ (0.1.7) | |
| Multi-car switcher + rename | ✅ | |
| Inbox / mark read / mark all | ✅ (needs overseas keys) | |
| FCM push + category channels | ✅ (needs stock Firebase file) | background notification-payload pushes unclassified |
| OTA check / live download / install now / schedule | ✅ (0.2, owner only) | |
| OTA cancel (stuck assignment) | ⚙️ 🟡 | |
| Digital key provisioning (owner + shared) | ✅ | stranded-key repair 0.2.1 |
| Proximity unlock / walk-away lock | ✅ at car | needs calibration; offline-first zones 0.2.7 |
| Proximity exclusion zones | 🟡 experimental | |
| Car-side passive entry (0x0151) | ⚙️ 🟡 | not honoured under clean-room key |
| Force-unlock (volume gesture on lock screen) | 🟡 | opt-in, secure lock required |
| Home-screen widget | ✅ (0.2.7) | |
| Wear OS companion (BLE lock/unlock, climate/charge relay) | ✅ | |
| Remote parking (RPA) | 🔴 ⚙️ | NAK 0x100a, needs DK 3.0/SE |
| CCC / Apple Wallet pairing probe | 🟡 probe | |
| BLE ping | ✅ diagnostic | |
| Animated 3D hero | ✅ 7GT, 7X (asset packs local only) | 0.2.9 |
| Classic hero card | ✅ all models (renders optional) | |
| Encrypted log share / copy + decrypt_log.py | ✅ | |
| App update checker (GitHub) | ✅ | |
| Android Auto Enhancement (EV routing, Waze HUD, speed cameras) | 🟡 experimental, opt-in, Android 13+ | 0.2.8–0.2.9 |
| Units: distance / pressure | ✅ | |
| Units: temperature | 🔴 setting not applied | always °C |
| 27 languages + RTL | ✅ | some screens hard-coded English |
| Notification tap deep link | 🔴 not handled | `EXTRA_DEEP_LINK` never read |

## 26. Supported vehicle models
- **Catalog / UI** (`CarCatalog`): Zeekr **001**, **X**, **7X** (innerCode CX1E), **7GT** (default fallback), **9X**. Unknown model strings render as 7GT with neutral paint if colour unknown.
- **Animated hero**: 7GT, 7X only (asset packs).
- **Verified on real cars**: 7GT (EU, author's car) — full feature set; 7X (Brazil/LA login + DK; AU paint/sunroof contributions). Others are cosmetic catalog entries; capabilities come per-VIN from the cloud, so controls adapt automatically.
- **AA energy profiles** (`:aa`): 001 RWD 100, 001 AWD 100, 001 FR, 7GT AWD 100, 7GT RWD 100, 7GT RWD 75, 7X 100, 009 116/140, X 66 kWh.
- **Markets**: EU verified; LA tested by contributor; SEA (Australia) partly working per CHANGELOG fixes; ME untested.

---

## 27. Rewrite notes / known gaps to fix
1. Wire auto-Sentry after manual lock (Vehicle tab, widget, force-unlock) — currently walk-away only.
2. Apply `tempUnit` to all temperature displays (and convert setpoints for display only; wire stays °C dot-decimal).
3. Handle `CarNotifier.EXTRA_DEEP_LINK` on launch (route to inbox/OTA/security).
4. Localize ForceUnlock / SendToCar strings and command titles.
5. `signOut` should probably reset `onboardingDone` (or update the comment).
6. Delete dead code (`ControlsScreen`, `SentryScreen`) or put behind dev flag; keep `CommandIcons` only if a catalog debug grid is wanted.
7. Charge-port in the Charge sheet uses cloud-only `control.send` while widget/wear use BLE-first `vehicleControl` — unify.
8. Navigation is an enum + `when` with full-screen takeovers via booleans (Inbox, Journey, CarShare, HeroLab); system back only handled in takeovers. A rewrite should use a real nav graph with back stack.
9. Optimistic states without car readback (fridge on, steering heat, ventilate, Sentry in widget, departure toggles) need explicit "assumed" UX.
10. All repository calls must stay off the main thread and be cancellable; current code mixes `rememberCoroutineScope` and `deps.appScope` (appScope used where the action must outlive the screen).
