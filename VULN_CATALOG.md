# RFID / NFC Vulnerability Catalog

Classifier reference for the RFID Stepper (LF) and NFC UID Stepper (HF) apps.
Verdicts are what the tool can honestly derive **passively, without keys** — from
the decoded LF protocol name, or the ISO14443-3A ATQA/SAK + DESFire `GetVersion`.
Compiled from public research (sources per row). Verdict legend:

- **BROKEN** — the card's crypto is publicly broken (cloneable with keys recovered). 💀
- **CLONE** — no read-auth / static ID → directly cloneable (UID/ID only). 💀
- **SECURE** — AES-class, no public cryptographic break (deployment can still be weak).
- **UNK** — cannot be determined passively.

The apps skull (💀) BROKEN and CLONE.

---

## LF — 125 kHz (RFID Stepper)

**There is no secure 125 kHz card.** Every decodable LF credential is a static ID
with no access-control crypto → read = clone (to a T5577/EM4305 blank). The app
therefore labels any decoded LF card **CLONE**. Detection = the lfrfid protocol name.

| Protocol (lfrfid name) | Security | Verdict | Note / source |
|---|---|---|---|
| EM4100 / EM4102 / EM-Marin | none, 40-bit static | CLONE | most common; read→clone. [Flipper blog](https://blog.flipper.net/rfid/) |
| HID Prox H10301 / HidGeneric | none, Wiegand+parity | CLONE | capture-replay; through-bag range. [KSEC](https://tagbase.ksec.co.uk/tutorials/clone-hid-prox2/) |
| Indala (I40134, FlexSecur) | obfuscation only | CLONE | "FlexSecur" ≠ crypto. [HID PDF](http://www.proxmark.org/files/Documents/125%20kHz%20-%20Indala/HID.Indala.FlexSecur.Technology.pdf) |
| AWID | none | CLONE | read→T5577 |
| Kantech ioProx XSF | obfuscation | CLONE | "Extended Secure Format" is a namespace, not crypto |
| Paradox, Keri, Pyramid, Viking, Jablotron | none | CLONE | all static-ID |
| Gallagher (125 kHz Cardax) | none at LF | CLONE | vendor urges migration off LF. [Gallagher research](https://github.com/megabug/gallagher-research/blob/master/formats/card-specific/125khz/125khz.md) |
| NexWatch / Securakey / PAC-Stanley / G-Prox-II / Noralsy | none / obfuscation | CLONE | regional; all cloneable |
| T5577 / EM4305 (writable) | none | CLONE | the clone blank itself; impersonates any of the above |
| FDX-B (134 kHz animal) | none, static | CLONE | not access control |
| **Hitag2 / HitagS / Hitag1** | **real cipher, BROKEN** | (usually NO-DECODE) | 48-bit stream cipher cryptanalyzed — Verdult & Garcia, *Gone in 360 Seconds*, USENIX Sec 2012 ([PDF](https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final95.pdf)). Stock Flipper **can't read** challenge-response LF, so a Hitag card usually shows as *no LF decode* — treat that as "possibly Hitag/HF-only, use a Proxmark". |

**Nuance:** "Secure format" names (FlexSecur, XSF, NexWatch descrambling) stop
cross-customer interoperability, not cloning. A T5577 clone is indistinguishable
from a genuine card by ID alone.

---

## HF — 13.56 MHz (NFC UID Stepper)

Detection = ISO14443-3A **ATQA + SAK**, plus DESFire **`GetVersion`** hardware-major
byte on ISO14443-4 cards. Several types **collide** on ATQA/SAK (noted).

| Card | ATQA / SAK (or GetVersion) | Security | Verdict | Attack / source |
|---|---|---|---|---|
| **Mifare Classic 1K** | ATQA 0004 / SAK 08 | Crypto1 | **BROKEN** | darkside/nested/hardnested — Garcia et al. ESORICS 2008; Courtois 2009 |
| **Mifare Classic 4K** | 0002 / 18 | Crypto1 | **BROKEN** | same |
| **Mifare Mini** | 0004 / 09 | Crypto1 | **BROKEN** | same |
| **Mifare Classic EV1** | 0004 / 08 (identical to 1K) | Crypto1 | **BROKEN** | hardnested |
| **Fudan/Infineon Classic clones** | 0004 / 08 (identical) | Crypto1 + HW backdoor | **BROKEN** | 2024 backdoor key + static-nonce — [Quarkslab](https://blog.quarkslab.com/mifare-classic-static-encrypted-nonce-and-backdoors.html), [eprint 2024/1275](https://eprint.iacr.org/2024/1275) |
| **DESFire original (MF3ICD40)** | SAK 20; GetVersion hw_major **0x00** | 3DES | **BROKEN** | EM/power side-channel key extraction — [Oswald & Paar, CHES 2011](https://iacr.org/archive/ches2011/69170208/69170208.pdf) |
| **DESFire EV1 / EV2 / EV3 / Light** | SAK 20; hw_major 0x01 / 0x12 / 0x33(0x30) / 0x08 | AES-128 | **SECURE** | no public crypto break (EV1 only lab side-channel, no fielded key extraction) |
| **Ultralight / UL-EV1 / NTAG 213/215/216** | ATQA 0044 / SAK 00 | none / 32-bit pwd | **CLONE** | no read-auth; clone to magic UID tag. amiibo cloning routine |
| **Ultralight-C** | 0044 / 00 (same family) | 3DES (write-gate) | CLONE/WEAK | data usually readable; 3DES gates writes only |
| **Ultralight-AES / NTAG 424 DNA** | 0044 / 00 (same family!) | AES-128 | **SECURE** | ambiguous — shares signature with plain UL/NTAG; needs GetVersion to separate |
| **Mifare Plus SL1** | 0004 / 08 (looks like Classic) | Crypto1 compat | **BROKEN** | inherits Classic attacks in SL1 |
| **Mifare Plus SL3** | SAK 20 | AES-128 | **SECURE** | AES only; can't confirm SL3 passively |
| **HID iCLASS legacy / Elite** | *not ISO14443-A* (Picopass) | 3DES + global key | **BROKEN** | global key from reader — Meriac "Heart of Darkness" 27C3 2010; Garcia et al. ESORICS 2012. *Tool can't read (not 3A).* |
| **HID iCLASS SE / SEOS** | *not ISO14443-A* | AES-128 (SEOS) | SECURE | no public break. *Tool can't read.* |
| **ISO15693 / iCode SLIX** | *not ISO14443-A* | none | CLONE | cloneable to magic 15693. *Tool can't read (different anticollision).* |
| **FeliCa (Suica etc.)** | *not ISO14443* | DES/AES mutual auth | SECURE | no public break; Lite weaker. *Tool can't read.* |
| **EMV bank card** | SAK 20, ATS; GetVersion fails | RSA/ECC+3DES/AES | UNK→SECURE(clone) | can't clone for payment; PAN readable + relay attacks (Basin et al.) |
| **SmartMX / JCOP** | SAK 20 (collides) | certified SE | SECURE | applet-dependent |
| **Generic ISO14443-4 / Type-4** | SAK 20; GetVersion fails | unknown | **UNK** | resolve via AID/PPSE select (beyond this tool) |

### Collisions the tool CANNOT resolve passively (labeled honestly)
- **SAK 08 / 18 / 09** → whole Crypto1 family (Classic, EV1, SL1, clones). All → **BROKEN** (safe: they're all broken), but genuine-vs-clone is invisible without active probing.
- **SAK 00 + ATQA 0044** → whole UL/NTAG family. Verdict ranges CLONE→SECURE (UL-AES/424). App shows **CLONE** (the common case) — a secure UL-AES/NTAG-424 would be mislabeled without a `GetVersion` storage-byte probe (future work).
- **SAK 20** → DESFire *or* Plus SL3 *or* EMV *or* JCOP. Resolved only for DESFire (GetVersion); others → **UNK**.

### Random UID
A 4-byte UID whose first byte is `0x08` is an ISO14443-3 **Random ID** (privacy
mode, common on DESFire EV1+/EMV/passports). Shown as `RND` — not a stable identity,
and a strong signal the deployment relies on the crypto layer, not the UID.

### Not broken — do not mislabel
DESFire EV1/EV2/EV3/Light, Mifare Plus SL3, NTAG 424 DNA, UL-AES, iCLASS SEOS,
SmartMX/JCOP, standard FeliCa, EMV cloning: **AES-128 has no public break as of 2026**
— only lab side-channel research with no fielded key extraction.

---

## Key sources
- Mifare Classic backdoor/static-nonce (2024): Quarkslab; eprint 2024/1275
- Crypto1 break: Garcia et al. "Dismantling MIFARE Classic" (ESORICS 2008); Courtois darkside (2009)
- DESFire MF3ICD40 side-channel: Oswald & Paar, CHES 2011
- iCLASS: Meriac 27C3 2010; Garcia et al. ESORICS 2012
- Hitag2: Verdult & Garcia, USENIX Security 2012
- Type identification: NXP AN10833 (MIFARE type identification); nfc-tools ISO14443A tables
- Flipper LF support list: blog.flipper.net/rfid
