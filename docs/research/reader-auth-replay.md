# Reader-Side MIFARE Classic / DESFire Auth, Replay & Nonce Leakage

Assumes a **card-emulating Flipper** probing a *reader* you're authorized to test.
Grounding fact (Quarkslab, eprint 2024/1275): *"It will always be possible to
recover the keys if an attacker has access to the corresponding reader."* The
reader is a standing oracle — that's what makes reader-side auditing productive.

---

## 1. mfkey32 / nested from the READER (nonce leakage)

Crypto1 (48-bit LFSR) was reverse-engineered by Nohl/Plötz/Starbug and dismantled by Garcia et al. The 3-pass auth leaks on the RF interface: `uid` (clear), `nT` (tag nonce — **the emulator chooses it**), `{nR}` (reader nonce, encrypted), `{aR}` (reader answer, encrypted). Two auths to the same sector/key = two `(nR, aR)` pairs → over-determines the LFSR → **mfkey32** recovers the key in seconds. `mfkey32v2` can need a single well-formed pair. This is Flipper's **NFC → Extract MF Keys ("Detect Reader")** → **MFKey** flow.

**What makes a reader vulnerable:** it's vulnerable the moment it speaks Crypto1 — you can't patch out nonce leakage while still reading Classic. Severity is about **what the key unlocks**:
- **Static keys (worst):** same Key A/B across the estate → one tap → clone-once/open-all.
- **Diversified keys (better):** each card's key derived (AES-CMAC/UID) from a SAM master → mfkey32 yields only *that card's* sector. Weak/known diversification collapses this.
- **Hardened / static-encrypted-nonce cards** resist *card-only* attacks but not reader-side mfkey32 (the reader still transacts).

Attack family context: **nested** (needs one known key), **darkside** (parity leakage, ~300–500 attempts, no known key), **hardnested** (ciphertext-only vs hardened, ~1600–2200 nonces), and **static encrypted nonce + hardware backdoor** (Quarkslab 2024): the Fudan **FM11RF08S** ships a static-but-encrypted nonce + a backdoor auth keyed with a production-wide key **`A396EFA4E24F`**, recovering *all user keys in minutes even when diversified*; analogous backdoors in FM11RF08/32, FM1208-10, **NXP MF1ICS5003/5004, Infineon SLE66R35**. Tooling: Proxmark `fm11rf08s_recovery.py`.

- **Flipper-testability: Direct** (stock firmware, end-to-end). **Severity: Critical** for any Classic reader with static keys.
- **Sources**: [Flipper mfkey32](https://docs.flipper.net/zero/nfc/mfkey32) · [FlipperMfkey](https://github.com/noproto/FlipperMfkey) · [Dismantling MIFARE Classic](https://www.cs.bham.ac.uk/~garciaf/publications/Dismantling.Mifare.pdf) · [Hardnested (CCS 2015)](http://cs.ru.nl/~rverdult/Ciphertext-only_Cryptanalysis_on_Hardened_Mifare_Classic_Cards-CCS_2015.pdf) · [Quarkslab blog](https://blog.quarkslab.com/mifare-classic-static-encrypted-nonce-and-backdoors.html) · [eprint 2024/1275](https://eprint.iacr.org/2024/1275)

---

## 2. Reader acceptance / replay flaws (testable by card emulation)

| Flaw | Mechanics | Flipper testability | Severity |
|---|---|---|---|
| **Clone acceptance** | Grants any card with correct UID+data; no original-silicon check | **Direct** — emulate an exact authorized dump | High |
| **No anti-passback / replay window** | Same credential accepted repeatedly, same direction | **Direct** — present N times | Medium–High |
| **Write-back / counter freeze** | Reader writes a counter/token back each tap; emulator refuses or replays a frozen value | **Partial** — log incoming WRITE/INC/DEC APDUs, NAK or serve frozen; finding = whether reader enforces | High |
| **Facility-code-only / UID-only** | Authorizes on FC/UID alone, skips crypto | **Direct** — emulate valid UID, refuse Crypto1 auth; grant = UID/CSN-only | Critical |
| **Random-UID acceptance** | Accepts a never-enrolled UID | **Direct** — emulate an invented `08`-prefixed UID | High |

**Highest-yield finding:** UID/CSN-only and FC-only readers make Crypto1 irrelevant — a UID copy (Flipper reads + emulates trivially) is a full clone. **Mitigation:** enforce authenticated reads; allow-list the cryptographic ID, not UID; anti-passback; alarm on duplicate-credential/UID.

---

## 3. DESFire reader-side — honest limits

- **Original DESFire (MF3ICD40, 3DES):** broken by Oswald & Paar (CHES 2011) via side-channel (~$3k rig). Card/hardware attack, not Flipper.
- **EV1/EV2/EV3 (AES-128):** protocol sound; reader-side weakness = integration errors — default AES keys, plaintext/`0x00` free-read files, readers that only read UID/unauthenticated files, or reliance on random-UID without binding.
- **What a Flipper can test:** mostly **Not** — the Flipper has **no DESFire Authenticate responder exposed to FAPs** and can't complete AES mutual auth as an emulated card (emulation drops at the reader's crypto challenge). **Partial:** emulate a UID-only DESFire-like target (detect CSN-only configs); read a plaintext/free file from a real card to assess whether authorization depends on unauthenticated data. **Not:** default-AES exploitation, AES emulation, 3DES side-channel — use a Proxmark3 (`hf mfdes`).
- **Severity:** default-key/free-file/CSN-only = High–Critical; proper EV2/EV3 = no practical Flipper attack.
- **Sources**: [Breaking DESFire MF3ICD40 (CHES 2011)](https://iacr.org/archive/ches2011/69170208/69170208.pdf) · [DESFire won't emulate (forum)](https://forum.flipper.net/t/mifare-desfire-wont-emulate/21253)

---

## 4. Diversified vs static keys

Static keys = estate key space of **one key**: recover once (mfkey32, default hit, or Fudan backdoor) → every card cloneable, every reader openable. Diversified keys make recovery **card-local** (blast radius = one badge) *if* the master lives in a SAM and derivation is strong. The Quarkslab backdoor defeats even sound diversification on affected chips — chip provenance matters as much as key policy.

**Detect static keys:** dump 3–5 enrolled cards — same Key A/B across distinct UIDs = static (Critical); common defaults (`FFFFFFFFFFFF`, `A0A1A2A3A4A5`, `D3F7D3F7D3F7`, `000000000000`) = static + guessable; keys varying per UID and resisting cross-card reuse = likely diversified; Fudan/clone fingerprint (ATQA/SAK/version, backdoor response) = flag regardless.

---

## 5. Timing / downgrade

| Behavior | Testability | Severity |
|---|---|---|
| **Protocol/format downgrade** — multi-tech reader honors the weakest format | **Direct** (present each; grant on weak = exposure) | High |
| **Auth-attempt timing** — distinguishes "auth failed" vs "unknown card" (recon for which sector to mfkey32) | **Partial** (timestamp reader commands) | Low–Medium |
| **Fallback-to-CSN on auth failure** — grants on UID after a failed auth | **Direct** | Critical |

Cryptanalytic timing side-channels vs Crypto1/AES are not practical from a Flipper (Proxmark/oscilloscope territory); the testable wins are **format downgrade** and **auth-failure fallback**.

---

## (a) "Reader Audit v2" feature spec

The Flipper emulates a card and **actively varies what it presents**, logging every reader command. Each test emits **PASS / FAIL / INCONCLUSIVE**; all require an operator-confirmed authorization flag.

1. **UID/CSN-only acceptance** — present a valid UID, hold no keys, NAK all auth. PASS = requires authenticated read. FAIL = grant with zero crypto (Critical).
2. **Cloned-card acceptance** — emulate a full authorized dump. PASS = distinguishes clone (e.g., per-tap counter). FAIL = grant (High; most Classic deployments FAIL by design — quantify it).
3. **Replay / anti-passback** — present the same credential N times, same door/direction. PASS = later same-direction denied/flagged. FAIL = unlimited repeats (Medium–High).
4. **Write-back behavior** — instrumented emulation logs every WRITE/INC/DEC/RESTORE. 4a refuse writes; 4b serve a frozen value. PASS = reader writes a per-tap token and rejects a non-advancing card. FAIL/INFO = no write-back, or write refused yet granted, or frozen value accepted (High).
5. **Random-UID acceptance** — invented UID. PASS = deny (identity bound to crypto ID). FAIL = grant (High).
6. **Nonce-leakage auto-collect (mfkey32) + static-key detection** — during every tap, run Detect Reader in the background, bank `(uid, nT, nR, aR)`, auto-crack; **cross-card correlation** → if a recovered key matches another audited card, flag **static key (Critical)**; keys differing per UID = likely diversified.
7. **Format downgrade / auth-failure fallback** — iterate presented format strong→weak (DESFire-plain → Classic-keys → Classic-UID-only → LF EM4100), and a card that starts strong auth then fails. PASS = only strong format honored. FAIL = grant on downgrade/after failure (High–Critical).

**Report object:** `{reader_id, timestamp, tests[], per_test:{result, severity, reader_command_trace, recovered_keys[], notes}, cross_card_key_matches[]}`.

Implementation: Tests 1, 3, 5, 6, 7 build on stock emulation + Detect Reader (FAP-level). Tests 2, 4 need a small **instrumented emulation FAP** that logs and selectively NAKs reader APDUs (the main engineering). DESFire stays limited to UID-only/plain-file cases — **do not claim mutual-auth emulation.**

## (b) Blue-team reader-audit checklist

1. **Kill CSN/UID-only mode.** No reader should authorize on UID/CSN/FC alone (Test 1/5). The #1 real-world failure.
2. **Confirm authenticated reads.** Authorization must depend on a successful crypto auth (diversified Crypto1 at minimum; ideally DESFire EV2/EV3 AES to an authenticated file — never a free/plaintext file).
3. **Prove keys are diversified, not static.** Dump 3–5 cards; keys must differ per UID and miss the default dictionary.
4. **Assume Crypto1 keys are recoverable from your readers.** Run mfkey32 (Test 6). A key opening >1 card = static-key emergency.
5. **Inventory chip provenance.** Identify Fudan FM11RF08/08S and other backdoored silicon; the `A396EFA4E24F`-class backdoor defeats even diversified keys.
6. **Enable anti-passback + duplicate-use alerting.** Deny/flag repeated same-direction use; alarm when a UID appears in two places or a counter fails to advance.
7. **Prefer readers that write & verify a per-tap token** — cheap anti-emulation on Classic.
8. **Block format downgrade** — multi-tech readers must not honor weaker formats or fall back to CSN after auth failure (Test 7).
9. **Migrate to DESFire EV2/EV3 (AES, mutual auth, diversified, EV2 proximity check) or SEOS.** Retire original DESFire (3DES).
10. **Retest after every reader/PACS firmware or config change** — downgrade/fallback reappear silently.
