# Recovering the missing wire formats

Doc 06 recovered the stock app's **interface surface** (endpoint paths, `CONTROL_TYPE_*`
command identities, capability codes, field names) from surviving string constants. Three
things it could **not** get statically, and this doc is how to get them:

| Missing piece | Why static failed | Best method |
|---|---|---|
| Exact `serviceId` + `serviceParameter` values for the NEW commands (e.g. V2L, smart-temp, PM2.5, sliding doors) | The base serviceId/param literals (`RDU`, `RCS`, `rsm=6`, …) are **not** in the dex strings at all — they're assembled at runtime. OpenZeekr's existing values came from live capture, not the APK. | **B. Live cloud capture** (authoritative), or **A. jadx** (often enough) |
| Request/response JSON schemas for the NEW endpoints | Model classes are minified; `@SerializedName` keys survive as strings but aren't tied to a class statically | **A. jadx** (read the model + Retrofit classes), confirm with **B** |
| BLE opcode **byte values** and frame body layouts (RPA/RSPA/FOB/NFC) | Only opcode **names** (`CMD_A2V_RPA_REQ`) survive; the `0x01xx` values and payloads are not in strings | **C. BLE/HCI capture** + **A. jadx** on the DK classes |

> All three are authorized only against **your own** account and car. Follow the project
> convention: publish interface shapes, never decrypted secrets/keys.

---

## Method A — Decompile with a real decompiler (jadx)

The pure-Python analyzer (androguard) failed here because the 80 MB dex ships a **falsified
header** (declares 4 classes). jadx does **not** rely on that header and decompiles the app
fine; it simply wasn't installable in the cloud sandbox (GitHub blocked). Run it on any machine
with internet.

**Setup**
```bash
# the base APK is inside the XAPK bundle (it's a zip)
unzip ZEEKR_3.1.2_APKPure.xapk -d zeekr_xapk
# -> zeekr_xapk/com.zeekr.overseas.apk   (199 MB base, the one with classes.dex)

# jadx: https://github.com/skylot/jadx/releases  (or: brew install jadx / scoop install jadx)
jadx-gui zeekr_xapk/com.zeekr.overseas.apk        # interactive, best for searching
# or headless, whole-app export:
jadx -d out --threads 8 zeekr_xapk/com.zeekr.overseas.apk
```
Memory: the single large dex wants a big heap — `jadx -Xmx8g` (or the gui's equivalent) if it
OOMs.

**Where to look** (search these in jadx-gui → Text/Full search):
- **Commands:** classes under `com/zeekr/snc/iov/model/base/control/factory/` —
  `createCommandByActionControl`, and each `*CommandCreator`. Each creator builds the body for
  one `CONTROL_TYPE_*`; read it to get the literal `serviceId`, `command` (`start`/`stop`) and
  the `serviceParameters` key/values. This is the direct answer to the biggest gap.
- **Endpoints + schemas:** Retrofit interfaces (search the path string, e.g.
  `"setSmartTemp"` or `ms-charge-manage`), then jump to the `@Body` type and its fields
  (`@SerializedName`). Do the same for responses.
- **Capability → feature mapping:** search a capability code (e.g. `ZK_CDS_PARKG_CLIMA_ACTV_1`)
  to see which screen/command it gates.
- **Signing (to cross-check doc 01):** search `X-SIGNATURE`, `HMAC`, `prod_secret` usage sites
  — confirms the canonical-string construction against our spec.

**Output discipline:** copy the recovered `serviceId`/params/JSON into
`docs/rewrite/06-stock-app-findings.md` beside each item (replace "command serviceId no" →
the real value). Do **not** paste keys or secret constants.

## Method B — Live cloud capture (authoritative)

The cloud is the ground truth: it confirms the serviceId/params actually accepted by *your*
car and the real response. This is how OpenZeekr's current values were obtained.

Two sub-approaches on your **own** device + account:

1. **Frida hook on the stock app** (no proxy, defeats pinning for free):
   - Hook OkHttp's `RealCall`/`Interceptor` chain, or `Request`/`Response` builders, and log
     method + URL + headers + body + response. A generic OkHttp logger script works.
   - Trigger the feature in the app (e.g. start V2L, set smart-temp) and read the exact body.
   - Also hook the signing primitives (`javax.crypto.Mac`, `SecretKeySpec`) to confirm which
     key signs the new endpoints — same technique the README already documents for the runtime
     keys.
2. **mitmproxy / HTTPS proxy** — works only if you bypass certificate pinning (Frida unpin
   script, or a patched APK). More setup than the direct Frida hook; use (1) unless you want a
   full session trace.

Capture **request + response pairs**; those double as the **golden test vectors** doc 00/README
asks for, so the rewrite's signing and models can be tested offline against known-good data.

## Method C — BLE / HCI capture (for DK opcode bytes)

For the digital-key / RPA / FOB / NFC opcode **values** and frame layouts:

1. Enable **Bluetooth HCI snoop log** in Android Developer Options (or capture with `btmon` /
   an external sniffer), reproduce the action with the stock app paired to the car.
2. Open the `btsnoop_hci.log` in Wireshark; filter ATT writes/notifications on the DK service
   UUID (doc 02 §2 has the UUIDs). The `FE 03 …` frames and their `0x01xx` cmdIds are visible.
3. Cross-reference the cmdId **names** from Method A (jadx on the DK classes) with the **bytes**
   on the wire to fill in the opcode table.
4. This is also the only way to confirm doc 02's open item: the `0x0121` status-push body
   layout and the fragmentation scheme.

## Prioritization

1. **jadx the command creators** (Method A) — one afternoon, recovers most new command wire
   bodies and endpoint schemas with no car needed.
2. **Frida cloud capture** (Method B) for the handful jadx leaves ambiguous, and to mint golden
   vectors.
3. **BLE capture** (Method C) only if you pursue the extended DK surface (FOB/NFC/RPA), which
   the car may still gate to Secure-Element keys (doc 02 §8, doc 05 §5).

## What to update when you have the data

- `docs/rewrite/06-stock-app-findings.md` — fill the "Wire known?" column with real values.
- `docs/rewrite/01-cloud-api.md` — add confirmed new endpoints/commands to the catalog.
- `docs/rewrite/02-digital-key-ble.md` — add confirmed opcode bytes.
- Capture vectors → a `testvectors/` fixture set for the rewrite's protocol-core tests.
