# HID iCLASS / Picopass / SEOS — Deep Research

Scope: defensive/pentest, owned or authorized systems. Verdicts use **Direct /
Partial / Not** for Flipper feasibility and distinguish **legacy vs SE vs SEOS**.

## 0. Verdict matrix

| Technology | Freq / stack | Crypto | Flipper read | Flipper clone | Severity |
|---|---|---|---|---|---|
| iCLASS **Legacy** (Standard key) | 13.56, iClass proto | Broken (global master key leaked) | **Direct** (Picopass app) | **Direct** (read+emulate+write magic) | Critical |
| iCLASS **Legacy Elite / High-Sec** | 13.56 | Broken (loclass recovers custom key) | **Partial** → Direct after key | **Partial → Direct** after key recovery | Critical (reader-side) |
| iCLASS **SE / SIO** | 13.56 + SIO wrapper | SIO signed/encrypted; keys recovered DEF CON 32 | **Partial** (detect "SE Enabled", NR-MAC) | **Not** on stock Flipper | High |
| **SEOS** | ISO14443A secure element | AES-128 mutual auth, keys in SE | **Not** (not iClass proto) | **Not** | Low (cloning) |
| **HID Prox / Indala / AWID / ioProx** | 125 kHz LF | None (static ID) | **Direct** | **Direct** (T5577) + brute-forceable | Critical |

---

## 1. iCLASS Legacy (13.56 MHz Picopass) — the broken model

### Card structure (8-byte blocks)
| Block | Name | Contents |
|---|---|---|
| 0 | **CSN** | 8-byte serial, read-only, diversification input |
| 1 | **Config** | fuses, app-area limits, OTP |
| 2 | **e-Purse** | anti-replay value, consumed on each auth (the "nonce" source) |
| 3 | **Kd** | debit key AA1 — write-only, diversified per card |
| 4 | **Kc** | credit key AA2 — write-only |
| 5 | **AIA** | Application Issuer Area |
| 6–9 | **AA1 / HID app** | **PACS data** — block 6 format descriptor, **Wiegand/PACS in block 7** (sometimes 7–9), 3DES-encrypted with a publicly-known transport key |

The **PACS** (the raw Wiegand FC + card# + format) is the credential. Recover Kd, decrypt block 7 → credential in the clear.

### Key diversification
- **Standard**: every card's Kd derived from **one global master key** diversified with the CSN. Recover it once → break every Standard card (300M+).
- **Elite/High-Sec**: site-specific custom master + extra fortification. Doesn't fix the cipher — attacker must recover *that site's* key (loclass).

### Research that broke it
- **Meriac, "Heart of Darkness" (27C3, 2010):** dumped the global Standard master key from reader firmware.
- **Garcia, de Koning Gans, Verdult, Meriac — "Dismantling iCLASS and iCLASS Elite" (ESORICS 2012):** full cipher/protocol/KDF reverse-engineering; six weaknesses; two attacks (Standard + Elite). Basis of loclass.
  - [Paper PDF](https://flaviodgarcia.com/publications/dismantling.iClass.pdf) · [Springer](https://link.springer.com/chapter/10.1007/978-3-642-33167-1_40)

### loclass (recovering the Elite custom key)
Exploits a chosen-CSN weakness: an Elite reader authenticates against attacker-chosen CSNs and returns a **MAC** each time. Present a fixed set of crafted "magic" CSNs (**~8–15**), capture the reader's MACs, solve **offline** (DES ops) for the reader's custom Elite master key. No 64-bit brute force. **This targets the READER.**
- [Proxmark loclass notes](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/loclass_notes.md) · [Swende: Elite Hacking](https://swende.se/blog/Elite-Hacking.html)

**Verdict:** Legacy Standard = **Direct** clone; Legacy Elite = **Partial** (loclass → Direct). **Critical.** **Mitigation:** disable legacy iCLASS at the reader; migrate to SEOS.

---

## 2. Flipper Picopass support

The Flipper ships a built-in **Picopass app** (@bettse, PR #1298, on the iceman/Proxmark work).

**Can do:** read iClass Legacy (standard/known keys, 3DES); **dump PACS** and save to LFRFID format; dictionary attack; **Elite Keygen / loclass online collection** (emulate the special CSNs, collect the reader's responses to a file for **offline** recovery — the reader-side loclass online phase, on the Flipper); emulate a legacy credential; write/change keys on writable "magic"/PAC iClass cards; **detect SE** ("Read Failed / SE Enabled"; some builds add NR-MAC capture).

**Cannot do:** read/clone iClass **SE**; write iClass SE; **SEOS** (not iClass). Offline loclass fails on non-iClass Picopass, iClass SE, Standard-2 keyset, SE-KDF readers.

**vs Proxmark `hf iclass`:** the Flipper app is a **subset port** (same loclass algorithm/dictionary). Proxmark remains fuller (`sim/dump/chk/loclass/permutekey`, SE/SIO community decoding, on-device solver). Flipper = field collector; Proxmark = lab tool.
- [Picopass app (PR #1298)](https://github.com/flipperdevices/flipperzero-firmware/pull/1298) · [Flipper HID iClass wiki](https://flipper.wiki/hidiclass/)

---

## 3. iCLASS SE / SIO / SEOS

### SE + SIO
SE wraps PACS in a **Secure Identity Object (SIO)** — signed/encrypted; the reader validates the SIO signature. A naive clone lacking a valid SIO is rejected. But: the SIO on early/standard SE can often be **read and re-encoded** if the underlying credential is exposed. **DEF CON 32 (2024)** — Javadi, Levy & Draffen reverse-engineered the SE reader/encoder chain of trust and **recovered cryptographic keys** (incl. iCLASS SE **CP1000 encoder** issues, HID advisories). SE is now a legacy-risk platform.
- **Verdict:** SE = **Partial** on specialized tooling / **Not** on stock Flipper. **High** (rising). **Mitigation:** migrate to SEOS; patch reader firmware; rotate SIO/encoder keys; disable SE fallback.
- [IPVM: iCLASS SE exploit](https://ipvm.com/reports/iclass-se-exploit) · [HID CP1000 advisory](https://www.securityinfowatch.com/access-identity/article/53095490/hid-divulges-vulnerabilities-to-its-iclass-se-cp1000-encoder) · [SE/SIO deep dive](https://freethestack.net/blog/iclass)

### SEOS
A genuine **secure element** (JavaCard-class, ISO14443A), PACS in an ADF protected by **AES-128** with mutual auth + session keys. Keys live in the SE, **not extractable**, per-issuer. **Clone-the-chip = effectively no.** Residual risk is elsewhere: reader **downgrade** to weaker legacy/SE, mobile provisioning, encoder/issuer key compromise, physical bypass.
- **Verdict:** SEOS = **Not** cloneable via Flipper. **Low for cloning.** **Mitigation:** disable legacy/SE fallback (kill downgrade), protect encoder keys, enforce mobile attestation.

---

## 4. Reader-side angle — loclass targets the READER

loclass attacks a **reader in Elite/High-Security legacy mode**, not a card:
1. Present crafted **CSNs** (emulated card reporting attacker-chosen serials).
2. The Elite reader returns a **MAC** per CSN.
3. Collect ~8–15 **(CSN, MAC)** pairs — the **online** phase.
4. Offline solver recovers the reader's **custom Elite master key**.
5. With the site key, diversify/clone any card for that site.

**Flipper can do the online collection** (Picopass loclass / Elite Keygen mode) — export nonces, solve on a host. Only works if the reader is **legacy Elite with the legacy KDF** (SE-KDF/Standard-2/SE readers don't fall). **Critical** where legacy Elite readers exist. **Detection signal:** a burst of authentications with anomalous serial numbers.

---

## 5. Other HID / legacy LF (125 kHz) — no crypto

| Tech | Format | Weakness | Flipper |
|---|---|---|---|
| **HID Prox H10301** | 26-bit: 8-bit FC + 16-bit card# | ~2^24; known FC → 65,536 card#; sequential issuance | **Direct** + brute-forceable |
| **Indala** | 26/27/29-bit PSK | no crypto; some obfuscated formats partial | **Direct**/Partial |
| **AWID** | 26/50-bit FSK | no crypto, sequential | **Direct** |
| **ioProx (Kantech)** | 26/32-bit | no crypto, sequential | **Direct** |
| **EM4100** | 40-bit | no crypto | **Direct** |

Small ID space + known/constant FC + sequential issuance → know one badge, enumerate neighbors; no reader rate-limit. **Critical** (trivial). **Mitigation:** replace 125 kHz prox with SEOS/mobile; layer PIN/biometric; alarm out-of-range FC/card#.

---

## 6. New capability for our toolkit

The Flipper's Picopass app already does the low-level read/loclass/emulate — **don't reimplement**. Add classification, orchestration, reporting, reader-side auditing:

1. **iCLASS/Picopass classifier** (replaces the vague "may be iCLASS" hint): from anticollision + SE-detect, bucket the target — *Legacy-Standard* (clonable now), *Legacy-Elite* (needs loclass), *SE/SIO* (out of stock-Flipper reach), *SEOS/not-iClass* — with a plain-English risk verdict.
2. **iCLASS Legacy PACS auditor:** default-key dictionary → decrypt block 7 → decode Wiegand/PACS → flag default/Standard key, weak custom key, sequential-issuance exposure.
3. **Reader-side loclass-nonce collector + handoff:** detect a legacy-Elite reader, drive the loclass online collection, validate enough good nonces, package for the offline solver; verdict *legacy-Elite = vulnerable* vs *SE-KDF/Standard-2/SE = not loclass-able*.
4. **LF Wiegand auditor / brute-force candidate generator:** decode HID Prox/Indala/AWID/ioProx, extract FC + card#, generate bounded neighbor/sequential candidate lists (authorized scope only).
5. **Unified authorized-scope report:** technology, clonability verdict, attack path, vendor-aligned mitigation.

Items 1, 2, 4, 5 are net-new software; item 3 is orchestration around the existing loclass online phase (offline solve stays on host/Proxmark). Nothing gives SE/SEOS **cloning** — that stays **Not** on a stock Flipper.
