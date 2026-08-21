# Reader-Side RFID/NFC Access-Control Vulnerabilities — Flipper Zero Audit Research

Scope: authorized/defensive testing only. Focuses on **reader-, panel-, and
credential-issuer-side** weaknesses that complement the toolkit's card-side fuzzing.
The Flipper is a capable LF (125 kHz) TX/RX device, a decent HF (13.56 MHz)
emulator/reader, and a flexible GPIO host — but a **poor HF over-the-air sniffer**,
and it **cannot break OSDP Secure Channel or modern crypto without keys**.

---

## 1. Wiegand protocol weaknesses (reader ↔ controller link)

### 1.1 Wiegand cleartext sniffing / credential harvesting
- **What**: The reader↔controller Wiegand signaling (D0/D1) is unencrypted, unauthenticated cleartext. Wire access = every badge number in plaintext.
- **Exploit**: Readers sit on the *unsecured* side of the door, often no tamper detection. Inline implants (ESPKey, BLEKey) tap D0/D1, log thousands of bitstreams, exfil over Wi-Fi/BLE. ~80% of office buildings still run raw Wiegand.
- **Flipper-testability**: **Direct.** GPIO decodes D0/D1 directly; community Wiegand app reads/saves/replays. Acts as an authorized "poor-man's ESPKey."
- **Severity**: **High** (Critical where the reader is externally accessible/untampered).
- **Mitigation**: OSDP v2 Secure Channel; reader tamper switches; wiring inside the secure boundary; line-idle anomaly monitoring.
- **Sources**: [BLEKey whitepaper (BH US-15)](https://blackhat.com/docs/us-15/materials/us-15-Evenchick-Breaking-Access-Controls-With-BLEKey-wp.pdf) · [ESPKey](https://www.redteamtools.com/espkey) · [Kisi: Wiegand vuln](https://www.getkisi.com/blog/hid-keycard-readers-hacked-using-wiegand-protocol-vulnerability) · [jamisonderek Flipper Wiegand app](https://github.com/jamisonderek/flipper-zero-tutorials/blob/main/gpio/wiegand/README.md)

### 1.2 Wiegand replay / bit injection (open-door)
- **What**: The controller trusts whatever appears on D0/D1; a captured bitstream re-injected opens the door. No nonce/sequence/MAC.
- **Flipper-testability**: **Direct** — the same GPIO app plays back a captured/synthesized frame to prove no anti-replay.
- **Severity**: **Critical** (full door bypass).
- **Mitigation**: OSDP Secure Channel; supervised/tamper reader mounts.

---

## 2. OSDP (SIA OSDP / IEC 60839-11-5) weaknesses

Bishop Fox's Petro & Vargas ("Badge of Shame," DEF CON 31 / Black Hat 2023) enumerated a dozen-plus issues and released the **Mellon** tap tool.

### 2.1 Install-mode / clear-text OSDP (Secure Channel never enabled)
- **What**: OSDP runs happily *without* Secure Channel; many integrators leave it unencrypted — "Wiegand over RS-485."
- **Flipper-testability**: **Partial.** GPIO + external MAX485 samples the differential pair; classifying encrypted vs cleartext (SCS markers vs plaintext `osdp_RAW`/`osdp_KEYPAD`) is realistic.
- **Severity**: **High.**

### 2.2 SCBK-D default/derived keys
- **What**: OSDP defines a hardcoded **SCBK-D** install key; the published 16-byte constant is `30 31 32 33 34 35 36 37 38 39 3A 3B 3C 3D 3E 3F` (ASCII `0123456789:;<=>?`) — **not** all-zeros. Many devices ship left on it.
- **Flipper-testability**: **Partial** (with RS-485 add-on) — probe could attempt SCBK-D handshake and report "accepts default key."
- **Severity**: **High.**

### 2.3 Secure Channel downgrade (capability-lie)
- **What**: The reader capability report and OSDP command byte are always unencrypted. A MITM rewrites the capability reply to claim "no crypto," and many controllers fall back to cleartext.
- **Flipper-testability**: **Partial** (RS-485 tap; injection needs bus drive). Detecting a controller that *accepts* a downgraded capability is a strong audit signal.
- **Severity**: **High.**
- **Sources**: [Bishop Fox Mellon](https://github.com/BishopFox/mellon) · [Badge of Shame (DEF CON 31 PDF)](https://media.defcon.org/DEF%20CON%2031/DEF%20CON%2031%20presentations/Dan%20Petro%20David%20Vargas%20-%20Badge%20of%20Shame%20Breaking%20into%20Secure%20Facilities%20with%20OSDP.pdf)

---

## 3. Reader/panel acceptance flaws

### 3.1 UID-only acceptance (HF)
- Reader authorizes on the ISO14443-A UID alone, no crypto. Cloning/emulating the UID grants access; DESFire random-UID and key diversification defeated because the backend never checks them.
- **Flipper-testability**: **Direct.** Emulate arbitrary UIDs; the existing Reader Audit classifies UID-only vs crypto by watching for RATS/auth.
- **Severity**: **Critical.**

### 3.2 No anti-replay / short replay window
- Reader accepts the same credential twice, or one it just read back. No nonce binding.
- **Flipper-testability**: **Direct at LF, Partial at HF** (HF sniffing weak; card-layer replay of static creds is easy).
- **Severity**: **High.**

### 3.3 Facility-code-only / truncation acceptance
- Panel checks only the facility code, or ignores/truncates ID bytes, collapsing keyspace.
- **Flipper-testability**: **Direct.** Extends the truncation/ID-sweep steppers into an **acceptance-oracle sweep** (hold FC, sweep card#, watch for "granted").
- **Severity**: **High.**

---

## 4. Credential format / issuer weaknesses

- **HID Prox 26-bit (H10301)**: 8-bit facility + 16-bit card# ≈ 24 bits, no crypto. With a known FC, sweep 65k card numbers. **Direct** on Flipper. **High.**
- **Sequential numbering / weak facility codes**: know one badge → neighbors ±N. **Direct** (stepper). **Medium–High.**
- **iCLASS legacy (shared master keys) & Elite**: global Standard master key published (Dismantling iClass, 2012); Elite recoverable via loclass. **Partial** on Flipper (Picopass app). **High.** See [iclass-picopass-seos.md](iclass-picopass-seos.md).
- **iCLASS SE / SIO key recovery (DEF CON 32, 2024)**: hardware key-material extraction from SE secure elements. **Not-with-Flipper.** **High** (ecosystem) but not Flipper-actionable.
- **Indala / AWID / EM4100 (LF)**: static, clonable, no auth. **Direct.** **High** where used for access.

---

## 5. Downgrade / multi-technology reader OR-logic

- Multi-tech readers (HID Signo, multiCLASS) ship in "migration mode" accepting **both** a secure HF credential **and** an insecure LF Prox/legacy-iCLASS — an implicit OR. "HID downgrade" is a documented Proxmark workflow: copy the secure ID onto a cheap LF tag.
- **Flipper-testability**: **Direct.** Present the same FC/card# as HF and as LF Prox; observe which the reader accepts.
- **Severity**: **High.**
- **Sources**: [HID: Safeguarding Against Legacy Downgrade (PDF)](https://doc.origo.hidglobal.com/common/rm/Safeguarding_Against_Legacy_Technology.pdf) · [Proxmark hid_downgrade.md](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/hid_downgrade.md)

---

## 6. Mifare Classic / DESFire reader-side crypto flaws

- **mfkey32 / nested (reader nonce leakage)**: two auths captured at the reader → recover the sector key. Flipper's native MFKey32 flow does this. A reader trusting Classic is trusting a broken cipher. **Direct.** **High.** See [reader-auth-replay.md](reader-auth-replay.md).
- **No mutual auth / static keys**: one key compromises the whole estate; UID-substitution passes if diversification isn't verified. **Partial** (Flipper logs auth depth, can't break AES). **High.**
- **Reader accepts cloned/emulated card**: no originality-signature check. **Direct** (emulate + observe grant). **Medium–High.**

---

## 7. Physical / relay attacks

- **Relay (proxy) attack**: proxy-card near the reader relays the RF exchange over a long link to a mole near the real card — defeats proximity even against DESFire/SEOS mutual auth. **Not-with-Flipper (practically)** — a single Flipper can't do a two-ended low-latency HF relay. **High** for high-value doors.
- **Long-range reader activation / skimming**: high-power coils read further than intended. **Partial** (Flipper is low-power). **Medium.**

---

## 8. Notable reader/panel firmware CVEs (credential/logic relevant)

| CVE / advisory | Product | Issue | Flipper relevance |
|---|---|---|---|
| CVE-2023-3938…3943 (24 flaws) | ZKTeco biometric terminals | QR SQLi → entry; file read leaks biometrics; RCE | Not Flipper (network/QR); scoping note |
| CVE-2021-36260 | Hikvision (shared firmware) | Unauth command injection → root RCE | Not Flipper; network |
| iCLASS SE key recovery (DEF CON 32) | HID iCLASS SE | Cryptographic key extraction | Hardware attack, not Flipper |
| Legacy iCLASS/Elite key disclosure (2012) | HID iCLASS legacy | Global shared master key | Flipper can detect readers still accepting legacy iCLASS |

Most reader *firmware* CVEs are network/web/injection bugs, not RF/credential-logic — scoping notes, not Flipper features.

---

## Top 5 new Flipper toolkit features (reader-side)

1. **Wiegand GPIO Sniffer + Replay ("WiegandTap")** — *New (GPIO).* Decode D0/D1, log FC/card# bitstreams, display and replay. Highest-value gap. Needs level clamp + MOSFETs.
2. **Multi-Tech Downgrade / OR-Logic Tester** — *Extends LF+HF steppers.* Present the same identity on HF and LF, report which the reader accepts.
3. **Acceptance-Oracle / Facility-Code Sweep** — *Extends truncation steppers + Reader Audit.* Hold FC, sweep card#, watch a Wiegand/OSDP tap or reader LED for "granted."
4. **OSDP Bus Probe ("OSDP-Peek")** — *New (GPIO + MAX485).* Classify cleartext vs Secure Channel, test SCBK-D, detect downgrade. Detect-only.
5. **Reader Crypto-Depth Classifier ("AuthDepth")** — *Extends Reader Audit.* Log how far the reader drives auth (UID → RATS → AID → CRYPTO1 → AES); pair with MFKey32.

Engineering ranking: #1 and #3 quick wins; #2/#5 moderate; #4 hardest (RS-485 + framing), scope as detect/classify.
