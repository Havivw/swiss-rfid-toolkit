# Reader-to-Controller Bus Attacks — Wiegand & OSDP

Targets the *wiring behind the reader* — the bus between the badge reader (at the
door) and the access controller (in a secure closet). The highest-value and
least-defended segment in most deployments. Authorized testing only.

---

## 1. Wiegand protocol internals — the plaintext bus

### Physical/electrical layer
- **Three wires:** `D0` (green), `D1` (white), `GND` (black). Reader power is separate (`+V`, typically 12 VDC, sometimes 5 V).
- **Idle-high, open-collector.** Both lines held **high** at interface voltage (commonly **5 V**, sometimes ~12 V) by pull-ups on the **controller** side. The reader transmits by pulling one line low.
- **Bit encoding:** a `0` = D0 pulses low (D1 high); a `1` = D1 pulses low (D0 high). Only one line active per bit.
- **Timing (SIA / de-facto):** pulse width (low) ~**20–100 µs**, typical **~50 µs** (ESPKey uses 40 µs). Bit interval ~**200 µs–20 ms**, typical **~1–2 ms** (ESPKey uses 2 ms). End-of-frame = line quiet > interval. No length field, start bit, or checksum at the wire.

### Data/format layer
- **26-bit H10301:** 1 leading even-parity, **8-bit facility code**, **16-bit card number**, 1 trailing odd-parity. That is the entire integrity mechanism.
- Other formats: 34/35-bit, HID Corporate 1000, 37-bit, plus proprietary 26–48+ bit. The controller is simply configured to expect a bit count.

### Why it's trivially attackable
No encryption/auth/nonce/session/rolling-code. Parity catches noise, not adversaries (attacker computes valid parity). No supervision of the data pair (classic Wiegand can't detect a spliced device). Whatever pulses D0/D1 in valid timing *is* an authenticated badge to the controller.

### How an attacker taps it
Reach D0/D1/GND (often by removing the reader — one security-Torx screw, pigtail in the back-box **outside** the secure area), then: **passive sniff** (high-Z tap, timestamp falling edges), **inline MITM** (cut and pass-through to log + suppress + inject), or **replay/inject** (drive lines low with ~50 µs/2 ms timing to present any captured/forged credential).

- **Severity: Critical.** **Mitigations:** OSDP Secure Channel; reader tamper switches; cable in conduit within the secure perimeter; controller on the secure side; monitor tamper + impossible-travel/duplicate-badge.
- **Sources**: [Franken "Gecko" (DarkReading)](https://www.darkreading.com/gecko-penetrates-building--access-systems/d/d-id/1129318) · [Franken BH-DC-08 (PDF)](https://blackhat.com/presentations/bh-dc-08/Franken/Presentation/bh-dc-08-franken.pdf) · [SecurityInfoWatch – Hacking the Wiegand Card Reader](https://www.securityinfowatch.com/access-identity/access-control/article/10558182/hacking-the-wiegand-card-reader) · [ESPKey manual](https://www.scribd.com/document/448531603/ESPKey-Tool-Manual-v1-0-0)

---

## 2. ESPKey and Wiegand implants

- **Zac Franken – "Gecko" (DEF CON 15, 2007 / BH DC 2008):** seminal inline Wiegand implant; captures plaintext credentials + replay. Core thesis: *Wiegand is plaintext, so a MITM on the data pair is game over.*
- **Bishop Fox – "Tastic RFID Thief" (2013):** weaponized long-range reader; feeds its Wiegand DATA0/DATA1 output to an Arduino that logs to `CARDS.txt`. Hardware-agnostic (consumes Wiegand). Walk-by harvesting.
- **Baseggio & Evenchick – "BLEKey" (Black Hat/DEF CON 23, 2015):** tiny implant **inline on D0/D1 inside the reader**, harvests every swipe, exfils over **BLE**, on-demand replay from a phone. *(Note: the first survey misattributed this to "Eric Van Albert" — correct authors are Baseggio & Evenchick.)*
- **ESPKey (octosavvi):** **ESP8266** inline logger/replayer/injector. Logs ~**80,000** bitstreams, Wi-Fi web UI to review + **replay on demand**, injects arbitrary Wiegand, drives lines low ~40 µs / 2 ms. Descendants: **ESP-RFID-Tool**, **The Tick**.

Why implants beat skimmers: an inline implant logs *every* badge ever used, and can replay/inject at will (forging parity itself) — persistent, remote, invisible to classic Wiegand.

- **Sources**: [ESPKey (GitHub)](https://github.com/octosavvi/ESPKey) · [Bishop Fox RFID Hacking](https://bishopfox.com/tools/rfid-hacking) · [BLEKey whitepaper (PDF)](https://blackhat.com/docs/us-15/materials/us-15-Evenchick-Breaking-Access-Controls-With-BLEKey-wp.pdf) · [NetSPI – A New Tastic Thief](https://www.netspi.com/blog/technical-blog/adversary-simulation/a-new-tastic-thief/)

---

## 3. Flipper Zero — Wiegand feasibility (concrete)

**Verdict: fully feasible, already implemented** (jamisonderek tutorial app / `wiegand_reader` in the catalog). Nuances are electrical, not computational.

### Pin assignment (matches the community app)
| Function | Flipper pin | Wiegand wire |
|---|---|---|
| Read D1 | **A7** | D1 (white) |
| Read D0 | **A4** | D0 (green) |
| Common | **GND** | GND (black) |
| MOSFET drive D1 | **A6** | → MOSFET → D1 |
| MOSFET drive D0 | **B3** | → MOSFET → D0 |

### Reading (sniff)
- A4/A7 as inputs with **falling-edge interrupts** (EXTI); timestamp each edge with the µs timer. D0→bit `0`, D1→bit `1`. End-of-frame on ~few-ms idle. 50 µs pulses / 2 ms spacing are trivially within STM32WB timer resolution.
- **5 V tolerance:** STM32WB GPIOs are **3.3 V**, only *some* pins 5 V-tolerant. Wiegand idles at 5 V+. **Add series resistor + clamp** (~1–10 kΩ series + 3.3 V Zener/Schottky to 3V3). Never present >3.6 V to a non-tolerant pin.

### Injecting / replaying
- Wiegand is **open-collector**: to send, **pull the line low** (never drive high — the controller's pull-up owns high). Use **open-drain output**, or a **MOSFET** (drain on D0/D1, source to GND).
- **Pull-down caveat:** Flipper GPIO can pull directly only if bus pull-ups are **≥ ~1 kΩ**. Strong pull-ups (~100 Ω) require **MOSFETs** (IRLZ44/IRL540-class) on **A6 (D1)** and **B3 (D0)**, gate ~4.7 kΩ pull-down.
- **Timing loop:** per bit, select D0/D1, assert low ~**50 µs** (40–100 µs), release, wait ~**2 ms**. Mask interrupts during the frame to reduce jitter.
- **Hazard:** driving a line low while the reader is transmitting = **bus contention/short**. Rule: only TX when the line is idle; never inject while a badge is being read.

### Existing apps/addons
- jamisonderek `flipper-zero-tutorials/gpio/wiegand`; `wiegand_reader` (catalog); "Flipper Zero RFIDThief" (phrack.me). Hardware addon: a proto-board with the two MOSFETs + gate pull-downs + input clamps.

- **Severity of a Flipper Wiegand tool: Critical** (same primitive as ESPKey, minus the leave-behind Wi-Fi implant).
- **Sources**: [jamisonderek Wiegand README](https://github.com/jamisonderek/flipper-zero-tutorials/blob/main/gpio/wiegand/README.md) · [wiegand_reader (catalog)](https://catalog.flipperzero.one/application/6883595c3a42809bf4b41f2a/page) · [Flipper GPIO docs](https://docs.flipper.net/zero/gpio-and-modules) · [Flipper RFIDThief](https://www.phrack.me/hardware/2025/02/26/Flipper-Zero-RFIDThief.html)

---

## 4. OSDP deep dive

OSDP (SIA / IEC 60839-11-5) fixes Wiegand: **supervised**, **multidrop**, optionally **encrypted**. "Optionally" is where deployments bleed.

### Link layer
- **RS-485** two-wire (A/B) differential, half-duplex, **multidrop**. Baud **9600 / 19200 / 38400 / 57600 / 115200 / 230400**. The **CP (controller) polls** each **PD (reader)**; card reads arrive as `osdp_RAW`/`osdp_KEYPAD`.

### Secure Channel (SC)
- **AES-128**, session derived from **SCBK** via a CP/PD random-challenge handshake (`osdp_CHLNG`/`osdp_SCRYPT`), then MAC + encryption.
- **SCBK-D** default/install key is **published**: `30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F` (ASCII `0123456789:;<=>?`). Not secret — in OSDP 2.2 and every library.
- **Install mode:** PD accepts SC under SCBK-D so the CP can push a real per-device SCBK via `osdp_KEYSET`. Meant to be transient.

### Real-world weaknesses (Bishop Fox "Badge of Shame" + `mellon`)
1. **Clear-text deployments** — SC off; RS-485 tap reads card numbers in the clear.
2. **Downgrade** — MITM rewrites `osdp_PDCAP` to claim "no encryption"; CP drops to clear text, no visible failure.
3. **Persistent install mode** — a rogue reader requests SC with the public SCBK-D and is accepted (or the attacker learns the SCBK).
4. **`osdp_KEYSET` capture** — no secure key exchange; the first real SCBK crosses the wire. Break the reader, wait for re-provisioning, capture the KEYSET → hold the site SCBK.
5. **Weak/guessable keys** — sample code / lazy integrators ship `04 04 04…` or `01 02 03…`.
6. **Plaintext command byte even inside SC** — packet *type* is always visible → easier MITM/analysis.

- **Severity: High → Critical by config.** OSDP done right (SC required, per-device random SCBK, install mode off, tamper monitored) is strong. As commonly deployed (clear text / SCBK-D / downgradeable) it is no better than Wiegand with a false sense of security.
- **Sources**: [Bishop Fox – Badge of Shame](https://bishopfox.com/blog/breaking-into-secure-facilities-with-osdp) · [BishopFox/mellon](https://github.com/BishopFox/mellon) · [SCBK-D value (BALTECH)](https://docs.baltech.de/refman/cfg/protocols/osdp/scbkeydefault.html) · [libosdp Secure Channel](https://libosdp.sidcha.dev/libosdp/secure-channel.html) · [SIA OSDP](https://www.securityindustry.org/industry-standards/open-supervised-device-protocol/)

---

## 5. OSDP — Flipper feasibility

RS-485 is differential; the Flipper has no RS-485 PHY. **Add a 3.3 V transceiver** (**MAX3485 / ADM3485** — matches Flipper 3V3):
- **A13 (USART1_TX)** → transceiver **DI**
- **A14 (USART1_RX)** → transceiver **RO**
- spare GPIO (e.g. **A15**) → **DE/RE** (hold in RX for passive sniff)
- **GND** common; transceiver A/B → OSDP bus A/B. For passive sniffing tie DE low.

**Realistic on Flipper:** auto-baud + OSDP-frame prober (SOM `0x53`, address, length, plaintext command byte); **cleartext-vs-Secure-Channel classifier**; **SCBK-D presence test** (STM32WB has an AES block); passive clear-text credential logging.

**Marginal:** active MITM **downgrade** needs **two RS-485 segments** bridged in real time at up to 230400 baud — the single USART makes reliable line-rate MITM fiddly.

**Not realistic (use laptop/Pi):** Bishop Fox `mellon` is a Python tool with **USB↔RS-485 adapters** (up to three) for full MITM/fuzzing/key-brute. The Flipper's honest niche is a **pocket triage prober**.

- **Sources**: [mellon README](https://github.com/BishopFox/mellon/blob/main/README.md) · [Flipper GPIO/USART pinout](https://docs.flipper.net/zero/gpio-and-modules)

---

## 6. Build specs for two Flipper apps

### App A — WiegandTap (GPIO sniffer / logger / injector)
**BOM:** 2× logic-level N-MOSFET (IRLZ44N/IRL540) + 2× 4.7 kΩ gate pull-downs; per-line input protection (~1–10 kΩ series + 3.3 V Zener/Schottky); optional optocouplers; tap leads.
**Pins:** Read `A4=D0`, `A7=D1`, `GND`; inject `B3=D0 gate`, `A6=D1 gate`.
**Firmware:** RX = falling-edge EXTI + µs timestamps, end-frame on ~3 ms idle, decode 26/34/37-bit (parity + FC/card#). TX = MOSFET, per bit low ~50 µs / period ~2 ms, recompute parity; **interlock: refuse TX during RX activity**. Store `facility,card,bitlen,raw_hex,timestamp` to SD; replay any stored frame.
**Limits:** operator-present (not a leave-behind implant); needs physical D0/D1 access; strong pull-ups need MOSFETs; 3.3 V GPIO needs clamping; TX-contention hazard.

### App B — OSDPProbe (RS-485 triage)
**BOM:** 1× 3.3 V RS-485 transceiver (MAX3485/ADM3485); switchable 120 Ω termination; A/B + GND leads.
**Pins (USART1):** `A13→DI`, `A14→RO`, `A15→DE/RE` (RX for passive), `GND`.
**Firmware:** auto-baud (9600→230400, validate OSDP frames); classifier (plaintext command byte → CLEARTEXT if `osdp_RAW`/`KEYPAD` in clear, SECURE if `osdp_CHLNG/SCRYPT/SCS`); SCBK-D MAC test → DEFAULT KEY flag; passive clear-text logger; keep DE disabled to never TX on a production bus.
**Limits:** single transceiver → passive triage, not reliable line-rate MITM (that's `mellon` on a laptop/Pi).
