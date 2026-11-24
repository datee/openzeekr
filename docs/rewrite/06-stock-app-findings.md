# Stock app static-analysis findings (interoperability RE)

**What:** Static reverse-engineering of the official **Zeekr overseas** Android app to catalog its
API / command / capability surface, so OpenZeekr can discover features it does not yet implement.
**App:** `com.zeekr.overseas`, versionName **3.1.2**, versionCode 30121, minSdk 26, targetSdk 35.
**Authorization:** this is authorized RE of the user's own app, for interoperability with the user's
own car. **Static only** — nothing was installed or executed.
**No secrets:** this document records **interface surface only** (endpoint paths, command ids,
parameter names, capability codes, field names, host names). **No secret/key values were extracted,
decrypted, or recorded.** The encrypted cert/key assets (`*.pem.enc`, `key*.enc`) were inventoried by
name only.

### Method & obfuscation honesty note
Source material: `strings` over the 80 MB single `classes.dex` (~798k lines, file-offset ordered),
`strings -e l` (UTF-16, near-empty — dex uses MUTF-8), the unpacked `assets/`, and androguard for the
binary `AndroidManifest.xml`.

Important limits, stated plainly:
* The dex is **heavily minified and its header counts are falsified** (declares 4 classes / 203
  strings for an 80 MB file), so **androguard could not walk the class/method/field tables** and no
  normal decompiler was available (jadx not installed, GitHub blocked). Everything below comes from
  **surviving string constants**: class names, enum **constant names**, resource ids, status-field
  names, and literal URL paths. These survive R8; **the literal `serviceId` and `serviceParameter`
  VALUES for remote commands do NOT** — `grep` for every known base serviceId (`RDU`, `RCS`, `ZAF`,
  `RSM`, …) returns **zero** standalone hits. OpenZeekr's existing command values (`RDU`/`stop`,
  `rsm=6`, `SH.11`, …) came from **live Frida captures**, not static strings, and this build confirms
  they cannot be recovered statically.
* Therefore, for **new** commands below I can give you the **command identity** (the readable
  `CONTROL_TYPE_*` enum name and the `*CommandCreator` class) and, where a capability code exists, its
  code — but **the exact wire serviceId/params for the new ones must still be confirmed by a live
  capture** on a car that has the feature. I flag this per item.
* Endpoint **paths** are exact and reliable. Capability **codes** are exact. Status/BLE **field and
  opcode NAMES** are exact; their numeric opcode values and body layouts are not in strings.

---

## 0. New capabilities worth adding — summary (most valuable first)

| # | Capability | Evidence | Wire known? | Priority |
|---|---|---|---|---|
| 1 | **V2L / vehicle-to-load discharge** (start/stop + set discharge SOC + live discharge V/A/kW/SOC) | `CONTROL_TYPE_DISCHARGING_ON/OFF`, `CONTROL_TYPE_SET_DISCHARGE_SOC`, `ms-charge-manage/.../getLatestDischargeSoc`, 10+ `disCharge*` status fields | endpoint yes; command serviceId no | High |
| 2 | **Car-side geofence** (create/update/enable/delete, circle **and polygon**, server alerts) | `ms-vehicle-defence/v1/fence/{create,update,enable,delete,page}`, `FencePolygonFragment`, `FenceCircleFragment` | endpoint yes | High |
| 3 | **Smart-temp / environment regulation** (one-shot combined climate preset) | `ms-remote-control/v1.0/remoteControl/setSmartTemp`, `EnvRegulationRequest`, `EnvRegulationCommandCreator`, `CONTROL_TYPE_ENV_REGULATION` | endpoint yes; body no | High |
| 4 | **Booking / valley (off-peak) charge V2** | `ms-charge-manage/api/v2.0/charge/{getBookingCharge,setBookingCharge}`, `remote-control/valley/query-charging`, `ChargingValleyRequest/Response` | endpoint yes | High |
| 5 | **Digital Key: FOB, NFC, transit card, approach/walk-away** | `ms-tsp-dkbs-geely/.../{create-owner-fob-key, write-owner-nfc-key, traffic-card/*, set-switch-of-approach-unlock, set-switch-of-walk-away-lock}` | endpoints yes | High (DK stack) |
| 6 | **Remote Parking Assist (RPA/RSPA)** over BLE | `CMD_RPA_*`, `CMD_RSPA_*`, `V_RPA_4`, `CMD_A2V_RPA_REQ`/`CMD_V2A_RPA_STATUS` | opcode names only | Med (car gates to SE keys) |
| 7 | **PM2.5 cabin air query + purification** | `REMOTE_OPEN_PM25_PURIFICATION`, `REMOTE_PM25_QUERY`, `CONTROL_TYPE_GET_PM_2P5`, `interior/exteriorPM25`, `airQualityIndex` | command ids only | Med |
| 8 | **Power sliding doors** (L/R open/close) | `CONTROL_TYPE_SLIDE_DOOR_{LEFT,RIGHT}_{OPEN,CLOSE}`, `SlideDoor*CommandCreator` | command ids only | Med (009/MPV) |
| 9 | **Camping mode & Parking comfort** (sustained climate while parked) | `CONTROL_TYPE_CAMPING_MODE_*`, `CONTROL_TYPE_PARKING_COMFORT_*`, `ZK_CDS_PARKG_CLIMA_ACTV_1`, status `campingModeState`/`parkingComfortState` | command ids only | Med |
| 10 | **Valet mode** (dedicated) & **Call-police/alarm** | `CONTROL_TYPE_VALET_MODE_*`, `CONTROL_TYPE_CALL_POLICE_*` | command ids only | Med |
| 11 | **Fast cool / fast heat** rapid climate | `CONTROL_TYPE_FAST_COOL/FAST_HEAT`, `key_ac_rapid_cooling_heating` | command ids only | Low |
| 12 | **Face recognition / driver face enrolment** | `ZK_face_recognition`, `remote-control/vehicle/face/{register,del}`, `FaceEntryRequest` | endpoints yes | Low |
| 13 | **Rich share plane** (histories, services edit, phone-based owner-share, default-share) | `ms-tsp-user-vehicle/.../vehicle-shares/*`, `ms-tsp-user/api/v2.0/ownerShare/*` | endpoints yes | Med |
| 14 | **TCAM dashcam wake / door config** | `remote-control/vehicle/familyNumber/AppWakeUpTcam/{vin}`, `ms-tcam-manage/.../queryDoorConfig`, `CONTROL_TYPE_WAKE_UP` | endpoints yes | Low |
| 15 | **eSIM traffic mall, road assistance, after-sales service orders, community/discover, loyalty points** | `overseas-app/{trafficMall,classification/service/road/assistance,after-sales/service-order,community,discover,userpoint}/*` | endpoints yes | Low (companion features) |

All 15 are **NEW** relative to OpenZeekr (`TspApi.kt`, `Command.kt`, docs 01 & 05).

---

## 1. Endpoints

Grouped by backend. "OZ?" = already in OpenZeekr (`TspApi.kt` / doc 01). Paths are verbatim from the
string pool; HTTP method is only shown where a request-class name or doc 01 fixes it.

### 1.1 TSP gateway — `ms-*` services (backend B)

| Path | OZ? | Notes |
|---|---|---|
| `ms-user-auth/v1.0/auth/login` | yes | TSP bearer login |
| **`ms-user-auth/v1.0/auth/logout`** | **NEW** | explicit server logout (OZ only clears token locally) |
| `ms-app-online-manager/api/v1.0/app/hb` | yes | heartbeat |
| `ms-app-bff/api/v4.0/veh/vehicle-list` (+v2.0/v3.0) | yes | garage (older versions present) |
| **`ms-app-bff/api/v{2,3,4}.0/veh/query/short-number`** | **NEW** | vehicle "short number" (likely short VIN / plate-free id) |
| **`ms-app-bff/api/v1.0/vehicle/modify/license/plate/number`** | **NEW** | set licence-plate number |
| **`ms-app-bff/api/v1.0/remoteControl/queryAirConSchedule`** | **NEW** | read scheduled A/C (RCC timer) |
| **`ms-app-bff/api/v1.0/remoteControl/queryFridgeData`** | **NEW** | read fridge (ZAE) setpoint/state |
| `ms-app-bff/api/v1.0/remoteControl/getVehicleState` | yes | live mode flags |
| `ms-vehicle-status/api/v1.0/vehicle/status/latest` | yes | full status |
| **`ms-vehicle-status/api/v1.0/vehicle/status/carFridge`** | **NEW** | fridge status read |
| **`ms-vehicle-status/api/v1.0/vehicle/status/powerMode`** | **NEW** | power-mode (`PowerModeStatusGetRequest`) |
| **`ms-vehicle-status/api/v1.0/vehicle/status/qrvs`** | **NEW** | "QRVS" quick status (heartbeat type `HEARTBEAT_TYPE_QRVS`) |
| **`ms-vehicle-status/api/v1.0/vehicle/status/vtm`** | **NEW** | "VTM" setting status (`getVtmSettingStatus`) |
| `ms-vehicle-capability/api/v1.0/vehicle/function/model/info` | yes | capability list |
| `ms-mno-service/api/v1.0/app/vehicle/data/usage/info` | yes | eSIM data usage |
| `ms-remote-control/v1.0/remoteControl/control` | yes | System-A control |
| **`ms-remote-control/v1.0/remoteControl/setSmartTemp`** | **NEW** | smart-temp / env regulation |
| `ms-charge-manage/api/v1.0/charge/control` | yes | charge control (RCS) |
| `ms-charge-manage/api/v1.0/charge/getChargingPlan` / `setChargingPlan` | yes | V1 charge plan |
| **`ms-charge-manage/api/v1.0/charge/getLatestSoc`** | **NEW** | latest SOC read |
| **`ms-charge-manage/api/v1.0/charge/getLatestDischargeSoc`** | **NEW** | **V2L** discharge SOC |
| **`ms-charge-manage/api/v1.0/charge/getLatestTravelPlan`** | **NEW** | last departure plan |
| **`ms-charge-manage/api/v1.0/charge/setTravelPlan`** | **NEW** | V1 departure (OZ uses v2.0) |
| `ms-charge-manage/api/v2.0/charge/{getTravelPlan,setTravelPlan}` | yes | V2 departure (ZAO) |
| **`ms-charge-manage/api/v2.0/charge/{getBookingCharge,setBookingCharge}`** | **NEW** | V2 booking/off-peak charge (OZ found it 400s on EU 7GT — kept for other cars) |
| `ms-vehicle-trail/v1.0/journalLog/{onOff,trip/listForPage,trackpoint/list}` | yes | trips |
| **`ms-vehicle-trail/v1.0/journalLog/delete`** | **NEW** | delete a trip record |
| **`ms-vehicle-defence/v1/fence/{create,update,enable,delete,page}`** | **NEW** | **car-side geofence** (circle + polygon) |
| **`ms-lbs-service/api/v1.0/invite` + `/{invitationId}`** | **NEW** | location-share invite (OZ only has v2.0 sendToCar) |
| `ms-lbs-service/api/v2.0/sendToCar` | yes | POI to nav |
| **`ms-tcam-manage/api/v1/downConfig/vehicle/queryDoorConfig`** | **NEW** | door-config (which doors powered; TCAM mgmt service) |
| **`ms-log/v2.0/log/upload/getossuploadtoken`** | **NEW** | OSS token for client-log upload (diagnostics) |

### 1.2 TSP — car sharing (richer than OZ)

OpenZeekr implements only `ms-tsp-user-vehicle/api/v2/veh/authorize/{acceptlist,accept,...}` and
`owner/authorize/{list,cancel,create}` + `owner/relation/modify-vehicle`. **All of the following are NEW:**

| Path | Likely purpose |
|---|---|
| `ms-tsp-user-vehicle/api/v1.0/vehicle-shares/details` | share detail (v1 plane) |
| `ms-tsp-user-vehicle/api/v1.0/vehicle-shares/owner/share-list` / `owner/share-histories` | owner share list + history |
| `ms-tsp-user-vehicle/api/v1.0/vehicle-shares/share/accept-histories` | accepted-share history |
| `ms-tsp-user-vehicle/api/v1/veh/owner/relation/set-default-vehicle` | set active/default car server-side |
| `ms-tsp-user-vehicle/api/v2/veh/authorize/{accept-histories,delete,finish}` | share lifecycle |
| `ms-tsp-user-vehicle/api/v2/veh/owner/authorize/{canShareVeh,cancel-force,car-sharing-histories,detail,modify/services,services,update-auth,delete}` | full owner-share admin, edit shared services, force-revoke |
| `ms-tsp-user-vehicle/api/v2/veh/owner/{checkAuth,share-status,upload/image}` | auth check, status, share photo |
| `ms-tsp-user-vehicle/api/v3/veh/owner/authorize/default-veh-share` | default-share config |
| `ms-tsp-user/api/v2.0/ownerShare/{bind,list,unbind,unbindToPhone}` | second share plane (phone-number based bind/unbind) |

### 1.3 TSP — Digital Key `ms-tsp-dkbs-geely` (backend B; much richer than OZ's BLE-only key)

OZ (doc 01 T30) lists owner/share **BLU** key + key-list/info/status only. **NEW endpoints:**

| Path | Purpose |
|---|---|
| `.../digital-key-center/create-owner-fob-key` + `activate-owner-fob-key` | physical **FOB** key provisioning |
| `.../digital-key-center/create-owner-nfc-key` + `write-owner-nfc-key` | **NFC** card/phone key |
| `.../digital-key-center/create-owner-blu-key` / `create-share-key` / `share-key` | BLE owner + share (OZ has) |
| `.../digital-key-center/{key-list,key-info,key-status,loop-key-status,sync-key-list}` | listings (OZ has) |
| `.../digital-key-center/get-bind-user-list` | users bound to a key |
| `.../digital-key-center/key-linked-share-account` | share-account linkage |
| `.../digital-key-center/{phonecoef,upload-ble-coef}` | BLE ranging **calibration coefficients** |
| `.../digital-key-center/{repush-key-to-vechile,remove-one-key,pairing-code}` | re-push / delete / pairing code (OZ has) |
| `.../digital-key-center/set-switch-of-approach-unlock` | **approach-unlock** toggle |
| `.../digital-key-center/set-switch-of-walk-away-lock` | **walk-away-lock** toggle |
| `.../v2.0/app/digital-key-center/{key-list,sync-key-list}` | v2 key plane |
| `.../traffic-card/{traffic-card-list,key-bind,key-unbind,get-card-status,get-partner-token,get-purchase-authority,set-default-cardface,delete}` | **transit/NFC payment card** management |
| `.../certificatecenter/create-app-certificate` | app cert (OZ has) |

### 1.4 ECARX "device-api" System-B — `remote-control/*` (PUT/GET, flat body)

OZ uses only `remote-control/vehicle/telematics/{vin}` (RDU_2/RDL_2). **NEW System-B paths:**

| Path | Purpose |
|---|---|
| `remote-control/vehicle/telematics/{vin}` | generic actuation (OZ has) |
| `remote-control/vehicle/status/{vin}` + `/state/{vin}` + `/soc/{vin}` + `/location` | status reads |
| `remote-control/vehicle/status/history/diagnostic/{vin}` | diagnostic history |
| `remote-control/vehicle/status/journalLog/{vin}` | trip-log status |
| `remote-control/vehicle/fragrance/{vin}` | fragrance control (dedicated) |
| `remote-control/vehicle/familyNumber/AppWakeUpTcam/{vin}` | **wake TCAM (dashcam/live)** |
| `remote-control/vehicle/face/{register,del}` + `app/faceInfo/{insert,delete}` | **face enrolment** |
| `remote-control/getFridge/status/{vin}` + `levc/getFridge/status` | fridge read |
| `remote-control/getLocker/status/{vin}` + `locker/secret/{vin}` | private-locker read + PIN |
| `remote-control/visitor/secret` | visitor-mode PIN |
| `remote-control/getVtmSettingStatus` | VTM setting |
| `remote-control/charging/reservation/{vin}` + `valley/query-charging` | reservation + **valley/off-peak** |
| `remote-control/schedule/{vin}` | schedules |
| `remote-control/user/authorization/{insert,selectRecord,selectRecordList,selectStatus,send/to/car,userDeleteAccount}` | authorization records |
| `remote-control/user/authorization/vehicle/geofence` + `/all/{vin}` + `/{id}` | **geofence (device-api side)** |
| `remote-control/user/authorization/status/journalLog/{vin}` + `vehicle/status/{vin}` | status |
| `remote-control/ihu/jou/{switch,switch/sendCommand,delete}` | CN-only IHU journey-log (OZ notes these 404 on EU) |
| `remote-control/v1.0/remoteControl/{control,setSmartTemp}` | mirror of TSP control |

### 1.5 Azure overseas-app (backend C) — companion/content surface (all NEW except noted)

OZ uses only `member/inbox*`, `ucd/service/vehicle/config/{vin}`, `ota/os/{versionV2,download,installation,cancel}`.

| Group | Paths (prefix `overseas-app/`) | Purpose |
|---|---|---|
| Inbox | `member/inbox`, `/home`, `/unread`, `/read-all`, `/{id}` | message centre (OZ has) |
| **OTA extras** | `ota/os/{version,versionV2,download,download-auth,installation,cancel,confirm,getConfig,setting}` | **`confirm`, `download-auth`, `getConfig`, `setting`, `version`(v1) are NEW** |
| Vehicle config | `ucd/service/vehicle/config/{vin}` | paint/series (OZ has) |
| **After-sales** | `after-sales/service-order/*` (create, cancel/{orderNo}, confirm/{orderNo}, store/list, favorite/store, onGoing/{vin}, service-proxy, get-store-resource) | book/track dealer service orders |
| **Classification/services** | `classification/service/{type/V3, road/assistance/V3/{vin}, trafficmall/service/entrance, vehicle/service/entrance/V3, bluetooth/white/list}` | service catalog incl. **roadside assistance**, **BT allow-list** |
| **Discover/news** | `discover/{news,tips,contact,more}` (+ browse/forward/thumbs/count), `news/{page,share}` | content feed |
| **Community** | `community/{follow/*, personal/center*}`, `post/{page,my/page,other/page,like,favorite,comment/*,topic/list}` | social |
| **Feedback** | `feedback/service/{save,page,detail,v3/*,getStoreList,submitEvaluation,reopen,getUrl}` | support tickets |
| **Loyalty** | `userpoint/overview`, `badge/{list,userList,updateAnimShown,wearSave}` | points & badges |
| **Traffic mall** | `trafficMall/{getAgreementInfo,getJumpInfo}` | eSIM data top-up |
| Stores/league | `store/{list,page}`, `league/store/*` | dealer/partner stores |
| Identity/consent | `oidc/v1/{code/{vin},getRealNameUrl/{vin}}`, `onetrust/service/*`, `protocol/service/{getProtocol,getSubscribeProtocol,subscribe}`, `user/service/{deactivate,cancel/revocation/period}` | real-name, consent, deactivate account |
| Misc | `cpr/relation/{list,getVehiclePlate/{vin}}`, `file/multi/upload`, `resource/config/assemble`, `version/control/show`, `tsp/service/{scan/code,vehicle/verification}`, `region/url` | plate, uploads, remote config, add-vehicle by scan/verify |

### 1.6 Message-core (backend C)
`open-api/v1/mcs/notice/receiver/equipment/relation/{sycn,disable}` — FCM register/unregister (OZ has).

---

## 2. Remote commands

**Full readable command vocabulary** = the `CONTROL_TYPE_*` enum + the `*CommandCreator` factory
classes (package `com/zeekr/snc/iov/model/base/control/factory/`). `createCommandByActionControl`
builds the ecarx `RemoteControlRequest` from each. **The wire serviceId/params are NOT in strings**
(see honesty note) — mapping `CONTROL_TYPE_*` → serviceId needs a live capture for the new ones.

| CONTROL_TYPE_ / Creator | In OZ `Command.kt`? | Note |
|---|---|---|
| UNLOCK / LOCK | yes | RDU/RDL |
| BACK_TRUNK_{OPEN,UNLOCK,LOCK} / HOOD_ON | yes | tailgate + frunk |
| FRONT/BACK_CHARGE_LID_{ON,OFF} | yes | RDO/RDC |
| AC_{ON,OFF}, DEFROST_{ON,OFF}, CABIN_{ON,OFF} | yes | ZAF/RCC |
| SEAT_HEAT_{ON,OFF}, SEAT_WIND_{ON,OFF}, STEER_WHEEL_{ON,OFF} | yes | ZAF |
| FRAGRANCE_{ON,OFF}, FRIDEG_{ON,OFF} / VEHICLE_REFRIGERATOR_{ON,OFF} | yes | RFD/ZAE |
| CHARGING_{ON,OFF}, SET_CHARGE_SOC, BATTERY_PREHEATING_{ON,OFF} | yes | RCS/ZAN |
| FLASH, FLASH_HORN, HONK | yes | RHL |
| SUNROOF_{ON,OFF,VENT}, WINDOW_{OPEN,CLOSE,VENT}, WIN_SUNSHADE_{ON,OFF} | yes | RWS |
| SENTINEL_{ON,OFF}, RSM_{ON,OFF} | yes | RSM=6 |
| PRIVATE_LOCKER_{LOCK,UNLOCK} / VEHICLE_LOCKER_{ON,OFF} | partial | OZ has private-lock; **VEHICLE_LOCKER is a separate locker** |
| VISITOR_MODE_{ON,OFF} | yes | ZAG |
| OPEN_RES / CLOSE_RES | yes | RES remote start |
| DRIVING_LOG_{ON,OFF} | yes | JOU |
| **STEER_WHEEL_AND_SEAT_HEAT_{ON,OFF}** | **NEW** | combined (one tap both) |
| **SLIDE_DOOR_{LEFT,RIGHT}_{OPEN,CLOSE}** | **NEW** | power sliding doors (MPV/009) |
| **CAMPING_MODE_{ON,OFF}** | **NEW** | sustained parked climate |
| **PARKING_COMFORT_{ON,OFF}** | **NEW** | parking comfort climate (`ZK_CDS_PARKG_CLIMA_ACTV_1`) |
| **VALET_MODE_{ON,OFF}** | **NEW** | dedicated valet (OZ only guessed rsm=123456) |
| **CALL_POLICE_{ON,OFF}** | **NEW** | emergency/alarm |
| **DISCHARGING_{ON,OFF}, SET_DISCHARGE_SOC** | **NEW** | **V2L discharge** |
| **ENV_REGULATION** / `EnvRegulationCommandCreator` | **NEW** | smart-temp combined preset → `setSmartTemp` |
| **FAST_COOL / FAST_HEAT** | **NEW** | rapid climate |
| **GET_PM_2P5 / GET_PM_2P5_TEMP / GET_TEMP** | **NEW** | on-demand cabin PM2.5/temp read |
| **PAA** / `PaaRemoteControlRequest` / `PaaSettingBean` | **NEW** | "PAA" group (parking air/assist) |
| **WAKE_UP** / `WakeUpCommandCreator` | **NEW** | wake vehicle/TCAM |
| **APPROACH_UNLOCK{,_ON,_OFF}, WALK_AWAY_LOCK, AWAY_LOCK_{ON,OFF}** | **NEW** | DK proximity toggles (also cloud switch §1.3) |
| **RSM_45_{ON,OFF}** | **NEW** | sentry **sub-mode 45** (distinct from rsm=6) |
| **OPEN_ZAT / CLOSE_ZAT** | **NEW** | serviceId **ZAT** comfort toggle (unknown function) |
| **CLEAR_DEFROST_{ON,OFF}** | **NEW** | rear demist / "clear" defrost |
| **SKY_LIGHT** | **NEW** | skylight (vs sunroof RWS_4) |
| **VLS** | **NEW** | unknown (vehicle location share?) |

New `_2` System-B serviceId variants present as bare tokens: `RWS_2`, `RCE_2`, `RCC_2`, `FTN_2`,
`FNC_1` (alongside OZ's `RDU_2`/`RDL_2`). Unknown serviceId families implied by capability codes:
**ZAJ, ZAM, ZAT, ZAZ, ZAP, ZAS** (see §3).

**Parameter keys** recovered (new in **bold**): `rcc.conditioner/ventilation/heat/level/target/temp/timerActivation/timerId/dayofWeek/startTimeofDay/endTimeofDay` (**the RCC timer set is richer** — OZ only sends conditioner/ventilation), `rcs.restart/terminate/setting/ac.current/dc.current`, `zae.model/temp`, `zad.model/code/boxId`, `zag.model`, `engStrtType`, `operation`, `channel_id`, `password`, `preHeatSts`, `creator`. Departure-plan beans expose `getCycleTimes`, `getFragSetting`, `preHeatSts` (consistent with doc 01 §4.3).

---

## 3. Capability codes (`ms-vehicle-capability` `functionCode`/`paramCode`/`paramValueCode`)

OZ matches substrings (doc 01 §6.4). Full surviving vocabulary — **bold = not referenced by OZ:**

**`C_*` function codes:** `C_RWS_4` (sunroof, OZ), `C_RES_1`, **`C_RWS_1`, `C_RWS_1_5`**, **`C_RCS_1`, `C_RCS_7`**, **`C_RDU_2_2`, `C_RDU_2_6`** (tailgate variants), **`C_ZAF_9`** (climate), **`C_ZAN_1`** (preheat), **`C_ZAO_1`** (departure), **`C_ZAJ_1`, `C_ZAJ_3`, `C_ZAM_1`, `C_ZAT_1`, `C_ZAZ_1`** (unknown comfort serviceId families), **`C_BTDOOR_1_1`** (BT door), **`C_PAA_1..9` (many: `_2_1.._2_4`, `_5_1.._5_4`, `_6`, `_7`, `_7_1`, `_7_2`, `_8`, `_9`)**, **`C_PAI_1`**, **`C_RBT_1_2`, `C_RBT_2_1`**.

**`V_*` value codes (non-codec):** **`V_RPA_4`** (remote parking), **`V_TYRE_1`** (tyre), **`V_CAR_TEMP_1`**, **`V_DKB_1/2/3`** (DK BLE), **`V_RCS_6_5`, `V_RCS_10_1_1/2/3`** (charging), **`V_RVS_5_7`**, **`V_LLCX_1`**, `V_ZAS_1` (visitor-ish), `V_RPA_4`.

**`T_*` type codes:** **`T_DKB_17`** (DK BLE), **`T_JL_1`** (journey log), **`T_ZAF_1`, `T_ZAF_CV_1`, `T_ZAF_RC_RW_1`** (climate sub-features), `T_ZAP_1` (OZ gloveboxish), `T_ZAS_1`, **`T_ORDER_1`**.

**`ZK_*` function names:** `ZK_remote_hood_control`, `ZK_remote_fridge_control` (OZ), **`ZK_remote_fridge_control_Advancer`**, **`ZK_face_recognition`**, **`ZK_remote_docking_control`** (docking/auto-charge?), **`ZK_sentry_mode`**, `ZK_storageBox_codeLock_control` + **`_01`/`_02`**, **`ZK_CDS_PARKG_CLIMA_ACTV_1`** (parking climate).

**`remote_control_*`:** `remote_control_{window,skylight_2,curtain_2,engine_start,lock,unlock,open,close,fragrance,ventilate_2,window_2,lock_2,unlock_2,fragrance_2}`, **`remote_control_card`** (NFC card key), **`remote_control_activate_switch`**, **`remote_control_alert`**.

**Seat vocabulary:** `main_driver_seat`, `copilot_seat`, `second_row_left`, `second_row_right`, **`third_row`** (6-seat MPV), `new_seat_heating_position`, `new_seat_ventilation_position`, `seat_{heating,ventilation}_{level,position,status}`, `remote_seat_preheat_switch`, `remote_seat_ventilating_switch`, `common_seat_heat_{one..six}_key` + vent (**up to 6 levels**, OZ assumes 0–3).

---

## 4. Digital Key (BLE / DK protocol)

Cloud DK endpoints: see §1.3. **BLE service:** `com.base.bluetooth.dk.DigitalKeyService`, intent action
`com.zeekr.snc.service.action.DK_START`; classes `TSPDigitalKeyManager`, `IDigitalKeyService`,
`ShareDigitalKey`, `DigitalKeyStatus`. GATT plumbing: `GATT_MAX_MTU_SIZE`, `EXTRA_SERVICE_UUID`,
`EXTRA_GATT_PROFILE`, `GATT_RESP_*`, `MSG_GATT_RESPONSE`.

**BLE opcode names** (values NOT in strings — need HCI captures to map bytes). Far richer than OZ's
`DkProtocol.kt`:
* **App→Vehicle** `CMD_A2V_*`: `CONTROL`, `CUST_REQ`, `PE_MODE_REQ`, `PAIRING_REQ`, `BOND_*`,
  `SEND_APP_CERT`, `SEND_APP_FACTOR`, `SEND_DKEY`, `DK_PRE_SYNC`, `RKE_ALLOW_REQ`, `HEART_TICK`,
  `WAKE_UP_POLLING`, `RSSI_SYNC`, `*CALIBRATION*` (big/small/self/gear/loc), **`RPA_REQ`**,
  **`RPA_ANSWER`**, `FOB_LISTREQ`, `FOB_ACTIVE`, `SUSPENSION_REQ/RSP`, `PHONE_STATE`, `TRANS`.
* **Vehicle→App** `CMD_V2A_*`: `VSTATUS_SYNC` (the encrypted status push OZ can't decode — doc 05 §3),
  `DK_STATUS`, `DK_VERIFY_STATUS`, `BOND_*_RESP`, `PAIRING_RESP`, `PE_MODE_RSP`, `RKE_STATUS_NOTIFY`,
  `APPROACHLOCK_NOTIFY`, **`RPA_CHALLENGE`**, **`RPA_STATUS`**, **`RPA_SYNC`/`RPA_SYNC2`**,
  `SEND_VEHICLE_CERT`, `SEND_VEHICLE_FACTOR`, `CALIBRATION_*`, `SYNC_PS_PARAM`, `FLOW_CONTROL`.
* **Remote Parking** (BLE, NEW): `CMD_RPA_{PARKIN_REQUEST,PARK_OUT_REQUEST,START_SEARCHING_SLOT,START_PARKING_IN,START_PARKING_OUT,CONTINUE,PAUSE,STOP,UNDO,REQ_MODE,OUT_MODE_SET,PRKG_ON,PRKG_OFF}` and straight-line `CMD_RSPA_{REQUEST,FORWARD,BACKWARD,COMPLETE,QUIT,BOTTOM_RELEASE}`. (Doc 05 §5 notes the car NAKs RPA for non-SE keys, so likely owner-DK-3.0 only.)
* **FOB over BLE:** `CMD_A2A_FOB_{LIST_RESP,PAIR_RESP}`, `CMD_A2V_FOB_*`.
* **DK config toggles:** `CMD_OPEN/CLOSE_{AUTH,BUTTON_COVER,HOME_SHOW,PLUG_CHARGE}`.

**Standards / SE:** `UWB`, `CCCKey`/`CCCKeyType`/`CCC_key`/`MODEL_CCC_KEY` (Car Connectivity
Consortium digital-key), `ec_dt.lic`/`kwpt.lincense`(sic) licence assets, and per-brand encrypted
cert pins `assets/{geely,lotus}_{prod,qa}_{cn,eu}_1..5.pem.enc`, `key1.enc`, `key2.enc` — **names only,
values not read**. These confirm NFC + FOB + UWB + CCC DK 3.0 well beyond OZ's BLE key.

---

## 5. Other backends / features

**Hosts (structure only; no values):**
* TSP gateways per region: `{eu,sea,la,me}-snc-tsp-api-gw.zeekrlife.com` (+ `-uat`/`-test`), plus
  `gateway-pub-{azure.zeekr.eu, aws-em-ae, hw-em-mx, hw-em-sg, em}.zeekrlife.com`, generic EM
  `gateway-pub-em.zeekrlife.com`, `snc-tsp-api.zeekrlife.com`, `snc-download-cdn.zeekrlife.com`,
  `gray-app.zeekrlife.com` (gray/beta). OZ already models EU/SEA/LA/ME.
* Azure overseas-app also appears as legacy `overseas-app.lynkco.com`, and
  `overseas-toc-{aws-fr-prod,hw-sin-prod}.zeekrlife.com`.
* **ECARX IoT / DK backend:** `api[s][v2]-{l,zk,vlv}?.ecloud{eu,kr,us}.com` / `.xchanger.cn`,
  `iot-gateway-api[-l][-stage/-test].ecloud{eu,kr}.com`, `iot-gwv2-api*.xchanger.cn`,
  `applog-api.ecloud{eu,kr}.com`. `assets/host.txt` + `urlconfig.properties` document the host
  construction: regions **EU, APAC, NA, SA, UAE, TUR**, env suffixes `-test`/`-stage`/`` (prod),
  brand variants **ZEEKR / LOTUS** and `gen1/gen2` **mutual-auth** (`apis…`) vs **single-auth**
  (`api…`) prefixes. (OZ only uses the xchanger session endpoint.)
* **Haohan energy/charging SDK** (`com.haohan.energesdk.*`, `MeepoDispatcherActivity`):
  `gateway[-pre/-prod/-release].haohanpower.tech`, `mini-energy-map-*`, `haohan-{socket,workorder,h5}-*`,
  `hh-wd-*.haohanpower.tech` — **public charging map / charge-point operator / work-order** network.
  Entirely absent from OZ.
* **HERE Maps SDK** embedded (`com.here.sdk.*`, `MapView`, energy models `assets/001-em`, `bx1e-em`,
  `geoviz`, `normal.day.json`) — in-app nav + EV routing. `HERE_logo_full*.svg`.
* **Huawei GRS** global-routing (`grs_sdk_server_config.json` → `grs.dbankcloud.*`), HMS ML Kit,
  Huawei push plumbing (`network-grs`, `hmsrootcas.bks`).
* Telemetry/consent: `guance.com` RUM (`eu1-rum-openway.guance.com`), **OneTrust** consent
  (`cevt-privacy.my.onetrust.com`, `mobile-data.onetrust.io`), Firebase/Crashlytics.
* `assets/dealerListEn.json` + `dealerListHe.json` (Hebrew — Israel market, `zeekr.co.il`),
  `discoverPage{En,He}.json` content.
* **Pay SDK** (`com.zeekr.overseas.paysdk`, `PayActivity`, deeplink host `pay`), **QR scan**
  (`DefaultCaptureActivity`), **ride** `mobile.starrides.com`.

**Status-model fields NEW vs OZ (doc 01 §5):**
* **Discharge/V2L:** `disChargeConnectStatus`, `disChargePower`, `disChargeIAct`, `disChargeUAct`,
  `disChargeSts`, `disChargeDegree`, `timeToTargetDisCharged`, `getLatestDischargeSoc`, `switchDischarge`.
* **Modes:** `campingModeActive`/`campingModeState`, `parkingComfortState`/`parkingComfortStatus`,
  `petModeStatus`, `approachUnlockSwitchStatus`, `walkAwayLockSwitchStatus`, `slideDoorLeft`/`slideDoorRight`,
  `wakeupflg`.
* **Air quality:** `interiorPM25`/`exteriorPM25`/`exteriorPM25Level`, `airQualityIndex`, `car_inner_pm25`.
* Power/VTM: `PowerMode`, `SNCVehicleQrvsStatusBean`, VTM setting status.

---

## 6. Assets inventory (purpose only — no dumps)

| Asset | Purpose |
|---|---|
| `SettingsConfig.json`, `ShareConfig.json` | **CN leftovers** — tiny WeChat/Weibo share + copy-link/reload stubs; not feature config |
| `001-em`, `bx1e-em` (+ `.manifest`), `Android`/`Android.manifest`, `geoviz` | **HERE map engine EV energy-model** packs (range/consumption routing) |
| `HERE_logo_full[_inverted].svg`, `location_indicator_*.obj/png`, `normal.day.json`, `style.data` | HERE map UI/style |
| `ZEEKR_OTA_20240511.bin` | bundled OTA/firmware sample blob (not read) |
| `ca.pem` | TLS CA bundle (not read) |
| `{geely,lotus}_{prod,qa}_{cn,eu}_1..5.pem.enc`, `key1.enc`, `key2.enc` | **encrypted DK cert pins / keys — names only, NOT decrypted** |
| `ec_dt.lic`, `kwpt.lincense` | DK/SDK licence files |
| `host.txt`, `urlconfig.properties` | **ECARX IoT host-construction config** (regions/brands/gen1-2 — §5) |
| `grs_sdk_server_config.json`, `grs_sdk_global_route_config_mlkit.json`, `grs_sp.bks`, `hmsincas.bks`, `hmsrootcas.bks` | Huawei GRS routing + HMS cert stores |
| `appbar_config_*.json` | in-app webview top-bar layout presets |
| `discover.json`, `discoverPage{En,He}.json`, `dealerList{En,He}.json`, `news`/`tips` | content-feed + dealer + Israel-market data |
| `ft_mcc_mnc_mini.json` | MCC/MNC carrier table (eSIM/traffic mall) |
| `demo*.html`, `jsbridge_test.html` | JS-bridge test pages |
| `filename.txt`, `proguardname.txt` | R8/ProGuard obfuscation dictionaries (explain minification) |
| `angle.ms`, `corner.ms`, `detect.ms`, `*.obj` | ML/parking-animation model + 3D assets |

---

## 7. Manifest

* **Package** `com.zeekr.overseas`; **custom URL schemes / deeplinks:** `zeekr-overseas://` and
  `zeekr-overseas-eu://` (matches FCM payload handling in doc 01 §7), plus host `pay` for the pay SDK.
  Entry/routing: `SchemeFilterActivity`, `TrampolineActivity`, `SplashActivity`, `HomeActivity`,
  `LoginActivity`, `MapToCarDialogActivity` (send-to-car), `PayActivity`.
* **Push/FCM:** `ZeekrFirebaseMessagingService` + `com.google.firebase.messaging.FirebaseMessagingService`,
  `NotificationReceiver`; device-token services `SyncDeviceTokenService` / `DisableDeviceTokenService`,
  `LogoutService`, `UploadCountryLanguageService`, `PrivacyAndTermsConsentService`.
* **Digital-key service:** `com.base.bluetooth.dk.DigitalKeyService` with action
  `com.zeekr.snc.service.action.DK_START`.
* **Widgets:** `ZeekrAppWidget`, `ZeekAppWidgettwo2two` (2×2), `ZeekAppWidgetFour2Four` (4×4) — OZ has a
  widget; stock ships two sizes.
* **Exported components:** 12 `android:exported="true"` (splash/scheme/trampoline/widgets/pay/FCM
  receivers — the usual launch + deeplink + push surface).
* **Permissions of note:** `NFC` (NFC digital key / transit card), `BLUETOOTH_ADVERTISE`/`SCAN`/`CONNECT`
  + `NEARBY_WIFI_DEVICES` + `LOCAL_MAC_ADDRESS` (DK/UWB), `CAMERA` (QR / face enrol / dashcam),
  `ACCESS_BACKGROUND_LOCATION` + `FOREGROUND_SERVICE_LOCATION`/`_CONNECTED_DEVICE` (geofence + BLE key),
  `SCHEDULE_EXACT_ALARM`, `SYSTEM_ALERT_WINDOW`. Third-party: Huawei HMS, Google finsky/AD_ID,
  `com.zeekrlife.sdk.permission.*`.

---

## 8. What still needs a live capture / real decompiler

1. **Wire serviceId + serviceParameters for every NEW command** (`CONTROL_TYPE_*` → `{serviceId,command,params}`):
   not in strings; needs Frida/mitm on a car that has the feature. This is the single biggest gap.
2. **BLE opcode byte values and `CMD_V2A_VSTATUS_SYNC` body layout** (offline status): needs btsnoop/HCI
   captures (doc 05 §3 already flags this).
3. **Request/response body schemas** for the new endpoints (geofence, setSmartTemp, booking/valley
   charge, discharge, door-config, share-services): class field names were not walkable because the
   dex defeats androguard; capture or a working decompiler needed.
4. **Meaning of unknown serviceId families** `ZAJ/ZAM/ZAT/ZAZ/PAA/PAI/RBT/VLS` and `RSM_45` — identified
   by capability code / control-type name only.
5. **Region segments** for ECARX IoT (NA/SA/UAE/TUR) are in `host.txt` but OZ only needs EU/SEA/LA/ME.
