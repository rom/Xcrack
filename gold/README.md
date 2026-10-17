# Gold-standard cross-validation fixtures

Xcrack's rule is that **every cryptographic scheme is cross-validated against an
external oracle** — a known-answer vector, a real third-party CLI's output, or a
reference implementation — never only against itself. This directory is the
**index and provenance record** for those external gold-standard fixtures, so
the cross-validation survives even if the original source moves or disappears.

The fixtures themselves are **committed in-tree** (nothing here depends on
fetching anything at test time). Most live next to the test that uses them, in a
package `testdata/` directory with an `ATTRIBUTION.md` recording where they came
from; a few canonical vectors are embedded directly in `_test.go` files. This
file is the single place that lists them all with their source, licence, and the
known answer each encodes. Generators that have no other home (e.g. the VBA DPB
oracle) are committed here under `gold/`.

> Provenance only. These are small, deliberately-weak or known-password sample
> artifacts for validating decryption; they contain no sensitive data.

## How to read this

- **Path** — where the fixture lives in the repo (its test consumes it there).
- **Source** — the external tool/version, project, or spec it came from.
- **Answer** — the known password / expected result it cross-validates.
- Where a directory already has an `ATTRIBUTION.md`, that file is authoritative
  for licence text and per-file detail; this table summarises it.

---

## Committed binary fixtures (third-party tools)

| Scheme | Path | Source | Answer |
| ------ | ---- | ------ | ------ |
| **Legacy MS Office** (RC4 CryptoAPI, XOR) | `xfileformats/formats/msoffice/testdata/` (+ `ATTRIBUTION.md`) | Vendored verbatim from **nolze/msoffcrypto-tool** (MIT), incl. byte-exact decrypted gold outputs | `Password1234_` (RC4), `123456789012345` (XOR) |
| **PDF** (RC4-40/128, AES-128, AES-256/R6 ×16 salts) | `xfileformats/formats/pdf/testdata/qpdf/` (+ `ATTRIBUTION.md`) | Produced by **qpdf** | user `userpw` / owner `ownerpw`, marker `CROSSCHECK-MARKER-7f3a1` |
| **Encrypted DMG** (encrcdsa v2) | `xfileformats/formats/dmg/testdata/*.dmg` (+ `ATTRIBUTION.md`) | Carved from genuine macOS-produced encrypted images | `opensesame` |
| **DMG John vectors** | `xcrypto/scheme/dmg/testdata/john_vectors.txt` | 13 vectors verbatim from **John the Ripper** `dmg_common_plug.c` | per-line (e.g. `vilefault`, `openwall`) |
| **KeePass** (KDBX4 Argon2d, KDBX3.1 AES-KDF) | `xcrypto/scheme/keepass/testdata/*.kdbx` (+ `ATTRIBUTION.md`) | **pykeepass 4.2.0** + **KeePassXC 2.7.6** (two independent oracles) | `opensesame` |
| **ODF** (AES-256-CBC) | `xfileformats/formats/odf/testdata/libreoffice-aes256cbc.odt` (+ `ATTRIBUTION.md`) | **LibreOffice 24.2.7.2** (`soffice`) | `opensesame` |
| **Apple iWork** (`.iwpv2` verifiers) | `xcrypto/scheme/iwork/testdata/*.iwpv2` (+ `ATTRIBUTION.md`); full docs `samples/apple.{pages,numbers,key}` | Saved from Pages/Numbers/Keynote **14.5** | `Password` |
| **age** (scrypt) | `xcrypto/scheme/age/testdata/hello.age[.asc]` | Real **age 1.1.1** CLI (`age -p`) | `correct horse battery staple` |
| **OpenPGP** (symmetric) | `xcrypto/scheme/pgp/testdata/hello.gpg[.asc]` | Real **GnuPG 2.4** CLI (`gpg -c`) | `correct horse battery staple` |
| **Header-encrypted 7z / RAR** | `xfileformats/formats/archive/testdata/hdr.{7z,rar}` (+ `ATTRIBUTION.md`) | `7z -mhe=on` / `rar -hp` | `Hunter2` |

## Embedded known-answer vectors (in `_test.go`)

| Scheme | Path | Source | Answer |
| ------ | ---- | ------ | ------ |
| **Ethereum keystore** (Web3 v3) | `xcrypto/scheme/ethkeystore/ethkeystore_test.go` | The two canonical **Web3 Secret Storage** vectors (geth / MyEtherWallet); scrypt MAC re-checked vs pycryptodome | `testpassword` |
| **Argon2d** | `xcrypto/prim/argon2/argon2_test.go` | **phc-winner-argon2** reference CLI v0x13 (command in comment) | e.g. `password`/`somesalt`, `keepass` |
| **RAR5** (PswCheck) | `xcrypto/scheme/rar5/rar5_test.go` | A real **WinRAR**/`rar -hp` archive | `opensesame` |
| **MS Access Jet4** header | `xfileformats/formats/access/jet_test.go` | **jackcess** (`PasswordUtil.setDatabasePassword`) | `SecretJet4!pass` |
| **Office agile / PDF / WinZip** hash-lines | `xcrypto/hashline/hashline_test.go` | **hashcat** canonical example hashes (`-m 9400/9500/9600/10500/10700/13600`) | `hashcat` |
| **PDF R6 / 40-bit** | `xcrypto/scheme/pdf/pdf_kat_test.go`, `keyattack_test.go` | Reference impl cross-checked vs **libqpdf 12.4.2** | `userpw`/`ownerpw` |
| **Legacy Office RC4/XOR KAT** | `xcrypto/scheme/officebinary/*_test.go` | **msoffcrypto-tool** doctests; Excel default | `password1`, `VelvetSweatshop` |
| **VBA project password** | `xcrypto/scheme/vbaproject/vbaproject_test.go` | Independent MS-OVBA + `hashlib` reference → [`gold/vba/vba_oracle.py`](vba/vba_oracle.py); corroborated by Didier Stevens | `Welcome1`, `s3cr3t!`, `nullseek2`, `LetMeIn2024` |

## Generators committed here

- [`vba/vba_oracle.py`](vba/vba_oracle.py) — independent Python reference for the
  MS-OVBA Data Encryption (§2.4.3.1) + Password Hash (§2.4.4.4 via `hashlib`),
  which produced the golden `DPB` blobs in `vbaproject_test.go`. Run
  `python3 vba/vba_oracle.py` to regenerate them. Kept here because the test
  embeds only its output, not the generator.

## Live (non-committed) cross-validation

Some schemes additionally cross-check against a CLI when present, skipping
cleanly when it is absent (so CI stays hermetic). These are belt-and-suspenders
on top of the committed fixtures above, not a substitute:

- `scripts/hashcat-xval.sh` — drives real **hashcat** (`-m 9600/10700/13600`).
- qpdf (`XCRACK_QPDF_LIVE=1`), `rar`, `7z`, `zip`, `gpg`, `age`, and **bkcrack**
  (`XCRACK_BKCRACK=/path`, Kévin Falcoz — the ZipCrypto known-plaintext oracle).

## Source references

Primary specs, RFCs, and tool/post citations are collected in
[`../docs/REFERENCES.md`](../docs/REFERENCES.md) §8; the per-scheme attack and
oracle notes are in [`../docs/CRACKING.md`](../docs/CRACKING.md) and
[`../docs/FILEFORMATS.md`](../docs/FILEFORMATS.md). The demo corpus (not gold
fixtures) is manifested in [`../samples/README.md`](../samples/README.md).
