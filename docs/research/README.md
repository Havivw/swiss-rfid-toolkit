# Reader-side RFID/NFC security research

Research corpus behind the toolkit's **reader-side** audit direction — what a
Flipper Zero (card emulation + LF/HF + GPIO) can detect or demonstrate against an
access-control **reader/panel**, beyond the card-side default-key fuzzing.

> ⚠️ **Authorized use only.** Everything here assumes owned or explicitly permitted
> systems (pentest engagement, CTF, research, your own lab).

## Contents

### Card-side (what the card is / can it be cloned)
| Doc | Topic |
|-----|-------|
| [vulnerability-catalog.md](vulnerability-catalog.md) | The card-side vulnerability catalog + detection signatures — the classifier reference behind the Stepper / Card Audit verdicts (BROKEN / CLONE / SECURE / UNK), sourced per row |
| [clone-and-vuln-reference.html](clone-and-vuln-reference.html) | The "can I clone this card?" (dd) model + full vulnerability matrix (open in a browser) |

### Reader-side (what the reader/panel does with the card)
| Doc | Topic |
|-----|-------|
| [reader-side-vulnerabilities.md](reader-side-vulnerabilities.md) | Broad survey of reader-side vuln classes + Flipper-testability + top-5 feature shortlist |
| [wiegand-osdp.md](wiegand-osdp.md) | The wire behind the reader — Wiegand tap/replay, ESPKey, OSDP Secure Channel / SCBK-D, + Flipper GPIO/RS-485 build specs |
| [iclass-picopass-seos.md](iclass-picopass-seos.md) | HID iCLASS legacy/Elite/SE/SEOS, loclass reader attack, Flipper Picopass limits |
| [reader-auth-replay.md](reader-auth-replay.md) | Mifare/DESFire reader-side auth, mfkey32-from-reader, replay/anti-passback, **Reader Audit v2 spec** + blue-team checklist |
| [proxmark5.md](proxmark5.md) | Status of the "Proxmark 5" and its claimed Flipper Zero integration |

## Honest limits (apply throughout)

- The Flipper is a **weak over-the-air HF sniffer** — HF work here is *emulation* +
  *reader-nonce collection* (mfkey32), not passive 13.56 MHz interception.
- **OSDP Secure Channel and modern AES credentials cannot be broken without keys** —
  those features are *detection/classification*, not cracks.
- **SE/SEOS cloning, DESFire mutual-auth emulation, HF relay, and secure-element key
  extraction** are out of a single Flipper's reach — documented as context, not features.
- All sweeping/brute-forcing must be gated behind explicit authorized-scope confirmation.

## Field-collect → host-solve

The heavy solves (loclass DES, mfkey cracking at scale, OSDP MITM) run on a **host**
(PC/phone with the Proxmark client, or Bishop Fox `mellon`). The Flipper is the
pocket **field-collection** device. See [proxmark5.md](proxmark5.md) — a Proxmark5
(pre-order, ~Oct 2026) is purpose-built to link directly to the Flipper for this handoff.
