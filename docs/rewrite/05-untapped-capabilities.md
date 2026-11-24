# Untapped capabilities

What the API, protocol and code already support but the current app (v0.2.9) doesn't expose,
plus what can be built on top. Found by tracing every `Command`, `TspApi` endpoint, status field
and BLE opcode to its live callers in `:app`, `:wear` and the widget (the dead `ControlsScreen`
and `CommandIcons` are excluded).

> ⚠️ Nothing in §1 and §3 has been exercised on a real car by this app. Treat each as
> "wire format known, behaviour untested" and test on your own vehicle first.

## 1. Implemented in code, no UI path

| Capability | Code | Wire | Gate / notes |
|---|---|---|---|
| Horn only | `Command.HONK` | `RHL start rhl=horn` | Only `FLASH` and `FLASH_HORN` are reachable. |
| Remote start / stop | `Command.ENGINE_START/STOP` | `RES start/stop`, `engStrtType=1`, 60 s duration | Capability `engineRes` (`C_RES`). On an EV, likely "remote power-on"; meaning unconfirmed. |
| Fragrance on / off | `Command.FRAGRANCE_ON/OFF` | `RFD start` / `RFD stop channel_id=0 level=0` | Capability `fragrance`. Channel/level parameters for "on" not mapped. |
| Private locker lock / unlock | `Command.LOCKER_ON/OFF` | `RDL start` / `RDU stop`, `target=private-lock`, `password=…` | **Password hard-coded to `"1234"`.** Needs a real PIN input before use. |
| Departure plan: seat heat/vent per seat, wheel heat, fragrance | `BookingTravelSetting.ventiSettings/heatSettings/whlSetting/fragSetting` | see 01 §4 | The car accepts them, but the app always sends `sts=0` (`ScheduleScreen.kt:458-483`), so plans only do cabin climate. |
| Inbox unread count (server side) | `TspApi.inboxUnread` | absolute URL, message-core | Never called; the badge is computed locally. |
| Parking snapshots | `TspApi.parkingSnapshots` | `/sentinel-monitoring-service/api/v1/pic/list` | Never called; same service as Sentry footage, so likely CN-only (404 on EU). |
| Remote-control live state | `TspApi.remoteControlState` | `ms-app-bff/.../getVehicleState` | Used only for journal-log state; may carry more live flags worth inspecting. |

## 2. Status fields parsed but never displayed

From `Models.kt` (`VehicleStatusBean` and children). 38 of 110 parsed fields have no consumer.
Some (`isCharging`, `chargerState`-style flags) are deliberately ignored as unreliable; see
01 §5 before trusting any of them.

| Group | Fields | Possible feature |
|---|---|---|
| Per-door locks | `doorLockStatusDriver`, `doorLockStatusPassenger`, `doorLockStatusDriverRear`, `doorLockStatusPassengerRear`, `trunkLockStatus` | "Rear-left door unlocked" instead of one overall lock state |
| Windows / roof | `winPosDriver/Passenger/DriverRear/PassengerRear`, `winStatus*`, `sunroofPos`, `sunroofOpenStatus` | Per-window position, "window open" alerts |
| Brake | `electricParkBrakeStatus` | Parked-safely check |
| Charging detail | `chargeUAct`, `dcChargePileIAct`, `dcChargePileUAct`, `chargeLidAcStatus`, `chargeLidDcAcStatus`, `dcDcConnectStatus`, `statusOfChargerConnection`, `isPluggedIn`, `timeToFullLabel` | Live charging session screen (V/A/kW, AC vs DC, time to full) |
| Efficiency | `averTraPowerConsumption` | Consumption display and trends |
| Mode / misc | `carMode`, `usageMode`, `runningStatus`, `preClimateActive`, `altitude`, `updateTime`, `seatHeatOn` | Show whether pre-conditioning is running; show the data's age |
| ICE / PHEV leftovers | `fuelLevel`, `fuelLevelPct` | Not relevant to Zeekr EVs |

## 3. Protocol features known but unused (BLE)

Constants in `core/.../ble/DkProtocol.kt`.

| Item | Code | Status | Value |
|---|---|---|---|
| **Vehicle status push** | `CMD_V2A_VSTATUS_SYNC 0x0121` | The car pushes it encrypted on the live session. The app ACKs it and uses it only for liveness (`RealDkSession.kt:718`); **the body is never decoded.** | Offline lock/door/window status with no internet. Highest-value item; needs captures to map the body. |
| Panic / search | `CTRL_PANIC_SEARCH 0x05` | Never sent | Offline alarm/find-car |
| Remote start | `CTRL_ENGINE_REMOTE_START 0x08` | Never sent | Offline counterpart to `RES` |
| Key inside / outside | `CTRL_KEY_INSIDE 0x09`, `CTRL_KEY_OUTSIDE 0x0B` | Never sent | Possibly feeds the car's own position logic |
| Car-side approach unlock / walk-away lock | `CMD_A2V_CUST_REQ 0x0151` (types 1/2), `CMD_A2V_PE_MODE_REQ 0x0196` | Developer-only; per 03 §25 not honoured for this key | Would move proximity into the car instead of the phone |
| Cabin ventilation | `CTRL_VENTILATION 0x12` | Mapped, but not to `WINDOW_VENT` | Offline cabin vent |

## 4. New features buildable on the existing API

No new reverse-engineering needed, just app logic over the command catalog (01 §6) and the
status poller (01 §5).

- **Automation:** MQTT / Home Assistant bridge; local intents for Tasker or Shortcuts; a
  documented, authenticated intent API.
- **History and analytics:** persist status snapshots. That gives detected charging sessions
  (energy, duration, cost per tariff, AC/DC), consumption per trip or season (trips already
  carry energy), SoC and range trends, and an odometer log.
- **Phone-side alerts:** left unlocked for N minutes, window or sunroof open plus a rain
  forecast (Open-Meteo is already used in `:aa`), charging stopped unexpectedly, charge target
  reached, tyre pressure drop (tyres in kPa), car offline for a long time.
- **Location rules:** pre-condition on leaving a place, open the charge port on arriving home,
  lock and arm Sentry on leaving a trusted area. Trusted areas and the location plumbing already
  exist.
- **Phone-side scheduled commands** for anything the car's own schedules don't cover.
- **Mobile data:** `trafficReport` (the car's SIM data usage) is fetched; it could get a proper view and
  a low-data alert.
- **Multi-car / fleet view:** the account already returns multiple vehicles.

## 5. Hard limits (not fixable client-side)

| Limit | Reason |
|---|---|
| Sentry footage / live view / snapshots | Service is unrouted outside China (404 `00A01`) |
| Remote parking (RPA) | Car NAKs (`0x100A`) any key that isn't a DK 3.0 / Secure-Element key |
| AC charge current on the EU 7GT | The car blocks it (`acRange=0`) |
| Single active session per account | Server policy; use a secondary, shared account |
| Anything beyond the stock app's API surface | New features need fresh decompilation of the stock app |

## 6. Suggested order

1. Departure plans with seats, wheel and fragrance (wire format already proven, UI only).
2. Per-door and per-window status, plus a live charging screen (data already parsed).
3. Horn, fragrance and remote start behind capability gates (test on the car).
4. Status history, then alerts and analytics on top of it.
5. Decode `0x0121` (needs HCI/btsnoop captures alongside matching cloud status).
6. Automation bridge.
