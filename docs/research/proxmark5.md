# "Proxmark 5" and its claimed Flipper Zero integration

**Researched: 2026-08-21**

## Bottom line
The claim is **substantially real, but not yet shipping.** "Proxmark5" is a
genuine, funded crowdfunding product from the actual RFID Research Group (RRG /
Iceman / ProxGrind — the real Proxmark3 team), and it **officially advertises
native Flipper Zero integration**, publicly endorsed by Flipper Devices. But it's
a **pre-order / Indiegogo campaign, not a buyable in-hand device** — units promised
for **October 2026**. Not vaporware, not a confusion with another product, but an
announced-and-funded product with an unshipped date; normal crowdfunding-slippage
skepticism applies.

## 1. Is there a "Proxmark 5"? — Yes (mid-2026)
- Launched on Indiegogo by RfidResearchGroup **12 May 2026** (Iceman announced on the Dangerous Things forum 11 May 2026). The genuine RRG team.
- **Funding:** ~**$1,036,645** from ~**3,036 backers** in 31 days; "Super Early Bird" sold out in <4 minutes; hit $600k+ stretch goals.
- **Status: PRE-ORDER, not shipping.** Ship target **October 2026** (KSEC reserved 100 units for Oct 2026). No production units in hand yet.
- **Claimed specs:** Arterytek AT32F435 (288 MHz Cortex-M4F), 512 KB SRAM / 1 MB flash, new FPGA, LF + HF (up to ~28 cm w/ Phase-2 antenna), UHF-ready via expansion, onboard battery, dual USB-C, open-source, backward-compatible with Proxmark3 RDV4 firmware (Iceman fork). ~£350 (KSEC).
- **Current shipping flagship remains the Proxmark3 RDV4.01** (Lab401, Hacker Warehouse, RedTeamTools, KSEC). Until Oct 2026, RDV4.01 is what you can actually buy.

## 2. Connects to a Flipper Zero? — Yes, its headline feature
- Proxmark.com / Indiegogo / KSEC: *"The Proxmark5 communicates directly with the Flipper Zero… Wired or wireless, the two devices operate as a single workflow."*
- **Mechanism:** **wired USB-C** (on-device handshake shown in demos); **wireless** via an optional **ESP32-C2 add-on** (BLE + WiFi + battery) for untethered pairing + mobile-app control. Flipper is **optional** — Proxmark5 runs standalone.
- **Official endorsement:** Flipper Devices posted *"The new Proxmark 5 will support interconnection with Flipper Zero! Best of luck with your crowdfunding campaign."*
- **Prototype demo** (Indiegogo update): Proxmark5 reading a Hitag2 card with the result shown on a Flipper Zero — a demo, not a shipped/reviewed product.
- **For existing Proxmark3:** no product-level Flipper integration. The only real Flipper↔PM3 interaction today is using a Flipper as a JTAG/DAPLink tool (OpenOCD) to un-brick/reflash a Proxmark3 — repair, not data interop.

## 3. Adjacent products often confused with it
- **Flipper WiFi Devboard (ESP32):** official Flipper WiFi add-on (Marauder etc.). Nothing to do with Proxmark.
- **Proxmark3 "Blue Shark" BLE module:** real RRG add-on giving an RDV4 Bluetooth to a **phone/PC app** — *not* to a Flipper.
- **HydraNFC:** separate NFC research shield/tool. Independent.
- **iCopy-X:** standalone automated cloner (Proxmark internals), touchscreen. No Flipper bridge.
- **DumpMe / BomberCat / Xelex:** niche gadgets; none is a Proxmark successor or the source of a credible Flipper-integration claim.

## 4. Chameleon Ultra (the common confusion)
- RRG/ProxGrind **8-slot NFC/RFID emulator + reader** (HF MIFARE/NTAG + LF EM/HID), USB-C + BLE 5.0, controlled by **its own** phone/desktop apps.
- **Connects to a Flipper?** **Not natively** — the Flipper BLE stack is peripheral/server-only (can't be a BLE central), so it can't connect out to the Chameleon's BLE.
- **Community workaround:** `muylder/Chameleon_Flipper` controls a Chameleon Ultra over **USB/serial** (BLE explicitly unsupported). Wired, experimental — not out-of-the-box.
- **Capabilities:** best *emulator* (multi-slot, stealthy) but weaker than Proxmark for deep protocol research; Flipper is the generalist. Loosely "Proxmark/Flipper-like," but does **not** natively bridge to Flipper.

## 5. The product making the claim
- **Name:** **Proxmark5** ("Iceman Edition"), by RFID Research Group.
- **Links:** [proxmark.com/proxmark-news/proxmark5](https://proxmark.com/proxmark-news/proxmark5/) · [Indiegogo](https://www.indiegogo.com/en/projects/rfidresearchgroup/proxmark5) · [KSEC pre-order](https://labs.ksec.co.uk/product/proxmark5-next-generation-rfid-research-platform-waiting-list/) · [BLE/WiFi add-on (ESP32-C2)](https://forum.ksec.co.uk/t/proxmark-5-ble-wifi-battery-add-on/17254) · [Flipper Devices endorsement (X)](https://x.com/flipper_net/status/2054636487254196714)
- **Credibility:** real and funded, but **pre-order — not yet shipping**. Risk: crowdfunding ship-date slippage (Oct 2026 target); the *wireless* Flipper link is a paid add-on module.
- **The connection:** **USB-C wired** (base) + **optional BLE/WiFi** (ESP32-C2) for untethered pairing — a real device-to-device link (Flipper as portable UI/relay for the Proxmark5), not just a shared phone app.

## What this means for the toolkit
Today's "Flipper collects → host solves" handoff (loclass DES, mfkey at scale,
OSDP MITM) runs on a **PC/phone with the Proxmark client** — the Flipper does not
drive a Proxmark3 over Bluetooth. The **Proxmark5 is purpose-built to fix exactly
that**: wired now, BLE via the add-on. If it ships as demoed (~Oct 2026), the
field-collect/host-solve workflow becomes an integrated Flipper↔Proxmark
toolchain instead of two separate devices plus a laptop.
