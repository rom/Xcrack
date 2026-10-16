# Xcrack — File formats & variants

A reference for **every format Xcrack recognizes and what variants of each it
handles**: how the format is detected, the encryption scheme(s) and their
parameters, how a password is verified, and which real-world tool each scheme is
cross-validated against. For commands and flags see [`USAGE.md`](USAGE.md); for
the tracked backlog of not-yet-implemented formats see
[`roadmap-enhancements.md`](roadmap-enhancements.md).

## How Xcrack sees a file

Each file is **detected** from a bounded peek of its leading bytes (a magic
number, and for ZIP-based documents a content sniff), producing a confidence in
`[0,1]`; the highest-confidence format that claims the bytes wins. A detected
format then has one or more **capabilities**:

| Tag | Capability | What recovery produces |
| --- | ---------- | ---------------------- |
| 🔓 | **Password-protected** | The password **and** the decrypted content (whole-file, or per-entry inside a container). |
| 📦 | **Container** | Child entries, unpacked and recursed into (entries may be individually encrypted). |
| 🔑 | **Key/credential store (verify-only)** | The **password**. The protected private keys / database body are reported but not reconstructed — recovering the passphrase is the deliverable. |
| 🧩 | **Known-plaintext** | Also supports a *no-password* key-recovery attack (see [`USAGE.md`](USAGE.md) `kp`). |

Every scheme is cross-validated against an independent oracle (a real CLI, a
known-answer vector, or a gold-standard decrypted document) — Xcrack does not
ship a scheme it cannot check. The `Scheme` column below is the identifier that
appears in challenges, JSON output, and the `identify` command.

---

## At a glance

| Family | Formats | Caps |
| ------ | ------- | ---- |
| [Archives & mail](#archives--mail) | ZIP, tar, gzip, bzip2, xz, 7-Zip, RAR, MIME `.eml` | 📦 🔓 🧩 |
| [Microsoft Office](#microsoft-office) | OOXML (`.docx/.xlsx/.pptx`), legacy binary (`.doc/.xls/.ppt`), Office family (Publisher/Visio/Project when encrypted), Access detection | 🔓 📦 |
| [Other documents](#other-documents) | PDF, OpenDocument (ODF), Apple iWork | 🔓 📦 |
| [Passphrase & messaging](#passphrase--messaging) | age, symmetric OpenPGP | 🔓 |
| [Keys & credential stores](#keys--credential-stores) | OpenSSH, PEM/PKCS#8, JKS, PKCS#12, PuTTY `.ppk`, SQLCipher, KeePass | 🔑 |
| [Disk images](#disk-images) | Apple encrypted DMG (via `dmg2john` `$dmg$` line) | 🔓 |

---

## Archives & mail

| Format | Detect | Scheme(s) / variants | KDF | Cipher | Verifier | Oracle |
| ------ | ------ | -------------------- | --- | ------ | -------- | ------ |
| **ZIP** 🔓📦🧩 | `PK\x03\x04` | `zipcrypto` (PKWARE legacy stream cipher); `winzip-aes-128` / `-192` / `-256` (AE-1 & AE-2) | ZipCrypto: bespoke 3×32-bit key schedule. WinZip: PBKDF2-HMAC-SHA1, 1000 iters | ZipCrypto stream; WinZip AES-CTR | ZipCrypto 1–2 check bytes; WinZip 2-byte password verifier + HMAC-SHA1 authentication | `zip`, `7z` |
| **tar / gzip / bzip2 / xz** 📦 | respective magic | *none* — compression/containers only | — | — | — | Go stdlib |
| **7-Zip** 📦🔓 | `37 7A BC AF 27 1C` | AES-256; **content-encrypted** and **header-encrypted** (`-mhe=on`) | SHA-256, iterated (`2^n` rounds) | AES-256-CBC | padding / stream check | `7z` |
| **RAR** 📦🔓 | `Rar!\x1A\x07\x00` (RAR4) / `...\x01\x00` (RAR5) | RAR3 (AES-128) and RAR5 (AES-256); **content-** and **header-encrypted** (`-hp`) | RAR5: PBKDF2-HMAC-SHA256; RAR3: custom SHA-1 | AES-CBC | RAR5 password-check value / CRC | `rar`, `unrar` (tests skip if absent) |
| **MIME `.eml`** 📦 | mail headers | *container* — decodes and extracts attachments (base64 / quoted-printable); encrypted attachments are handed to their own format | — | — | — | — |

**ZipCrypto note.** ZipCrypto is cryptographically broken. Beyond password
guessing, Xcrack implements the full Biham–Kocher **known-plaintext** key
recovery (🧩, the `kp` subcommand): given ~12 known plaintext bytes it recovers
the internal key state with no password — in pure Go, or offloaded to a local
`bkcrack` binary.

---

## Microsoft Office

| Format | Detect | Scheme(s) / variants | KDF | Cipher | Oracle |
| ------ | ------ | -------------------- | --- | ------ | ------ |
| **OOXML** `.docx/.xlsx/.pptx` 🔓 | OLE2/CFB compound file holding `EncryptionInfo` | `ooxml-agile` (Office 2010 & 2013) and `ooxml-standard` (Office 2007) | agile: iterated hash (configurable **SHA-1 / SHA-256 / SHA-384 / SHA-512**, `spinCount` ~100 000); standard: SHA-1 × 50 000 | agile: AES-128 or **AES-256**-CBC; standard: AES-128-ECB | gold-standard decrypted docs; `$office$` hashcat export (see below) |
| **Legacy binary** `.doc/.xls/.ppt` 🔓 | OLE2/CFB compound file | `office-rc4-cryptoapi-sha1` (Office XP/2003), `office-rc4-md5` (Office 97/2000), `office-xor` (XOR obfuscation) | RC4 CryptoAPI: SHA-1; RC4 97-2000: MD5; XOR: table | RC4 / XOR | RC4 CryptoAPI: byte-for-byte vs reference decrypted Word/Excel/PowerPoint |

**Legacy-Office scope.** RC4 CryptoAPI is fully decrypted and cross-validated
for Word, Excel, and PowerPoint. Office 97/2000 RC4 and XOR obfuscation are
implemented and unit-tested; XOR *content* reconstruction is wired for Excel but
not Word (no reference oracle), and only the main document streams are decrypted
(auxiliary encrypted streams are left as-is).

**Wider Office family (Publisher / Visio / Project / Access).** An *encrypted*
Office file of any application is the same CFB container — an `EncryptionInfo`
stream plus an `EncryptedPackage` — so detection is content-first and
extension-independent: encrypted **Publisher** (`.pub`), **Visio**
(`.vsd`/`.vsdx`) and **Project** (`.mpp`) that use the standard agile/standard
Office encryption are recovered through the same `ooxml` path as `.docx` (there
is no way to tell them apart before decryption; the application only shows in
the decrypted payload, which the engine then decomposes). **Access** is the
exception — `.mdb` (Jet) and `.accdb` (ACE) are *not* CFB files; the `access`
format detects and names them (jet3/jet4/ace) by their `Standard Jet DB` /
`Standard ACE DB` signature. Known gaps: Access password *recovery* is staged
(no validated oracle in this build), and pre-2007 Publisher/Visio/Project
binaries that used bespoke RC4-in-stream encryption are not yet decoded.

### OOXML agile variants (hashcat `$office$` version)

| Office | `hashAlgorithm` | Key | hashcat version | `-m` |
| ------ | --------------- | --- | --------------- | ---- |
| 2007 (standard) | SHA-1 ×50 000 | AES-128-ECB | `2007` | 9400 |
| 2010 (agile) | SHA-1 | AES-128-CBC | `2010` | 9500 |
| 2013 (agile) | SHA-512 | AES-256-CBC | `2013` | 9600 |

---

## Other documents

| Format | Detect | Scheme(s) / variants | KDF | Cipher | Verifier | Oracle |
| ------ | ------ | -------------------- | --- | ------ | -------- | ------ |
| **PDF** 🔓 | `%PDF-` | Standard Security Handler: `pdf-rc4` (V1/V2), `pdf-aesv2` (V4), `pdf-aesv3` (V5); revisions **R2–R6**; **user and owner** passwords | MD5-based (R2–R4); SHA-2 hardened hash "Algorithm 2.B" (R6) | RC4 (40–128-bit) / AES-128-CBC / AES-256-CBC | `/U` and `/O` strings | `qpdf`; `$pdf$` hashcat export |
| **OpenDocument (ODF)** 🔓📦 | ZIP whose first member is an `vnd.oasis.opendocument` `mimetype` | `odf-aes256-cbc` and `odf-aes256-gcm` (ODF 1.3); legacy Blowfish-CFB is detected and reported unsupported | PBKDF2-HMAC-SHA1 over a SHA-256 "start key" | AES-256-CBC or AES-256-GCM, per entry | CBC: SHA-256 checksum of the first 1 KiB; GCM: the 128-bit auth tag (no false positives) | LibreOffice 24.2 (CBC); W3C-spec round-trip + Go stdlib GCM |
| **Apple iWork** `.pages/.numbers/.key` 🔓 | ZIP of IWA parts containing a `.iwpv2` passphrase verifier | iWork '13+ (`iwork`) | PBKDF2-HMAC-SHA1 → 16-byte key | AES-128-CBC | `sha256(plain[0:32]) == plain[32:64]` over the decrypted verifier | reverse-engineered from Pages/Numbers/Keynote **14.5** and cross-checked against the known passphrase (passphrase only; document body not reconstructed) |

### PDF revision ↔ cipher ↔ hashcat mode

| V | R | Cipher | hashcat `-m` |
| - | - | ------ | ------------ |
| 1–2 | 2 | RC4 (40-bit) | 10400 |
| 2–4 | 3–4 | RC4-128 / AESV2-128 | 10500 |
| 5 | 5 | AES-256 (legacy) | 10600 |
| 5 | 6 | AES-256 | 10700 |

---

## Passphrase & messaging

| Format | Detect | Scheme / variants | KDF | Cipher | Oracle |
| ------ | ------ | ----------------- | --- | ------ | ------ |
| **age** 🔓 | `age-encryption.org/v1` header, or the `-----BEGIN AGE ENCRYPTED FILE-----` armor | `age-scrypt` — the scrypt passphrase recipient (binary **and** ASCII-armored input) | scrypt | ChaCha20-Poly1305 | `age -p` |
| **Symmetric OpenPGP** 🔓 | OpenPGP packet stream, or `-----BEGIN PGP MESSAGE-----` armor | `openpgp-s2k` / `openpgp-cfb` — `gpg -c` symmetric messages (binary **and** armored) | String-to-Key (simple / salted / iterated-salted) | the message's cipher (CAST5 / AES / 3DES / …) in OpenPGP-CFB | `gpg -c` |

---

## Keys & credential stores

These are **verify-only** (🔑): Xcrack recovers the passphrase; the protected
private keys or database body are surfaced as-is, not reconstructed.

| Format | Detect | Scheme / variants | KDF | Verifier | Oracle |
| ------ | ------ | ----------------- | --- | -------- | ------ |
| **OpenSSH private key** | `-----BEGIN OPENSSH PRIVATE KEY-----` | `openssh-key` — bcrypt-pbkdf + AES-CTR | bcrypt-pbkdf | successful decrypt + `x/crypto/ssh` parse | `ssh-keygen` |
| **PEM / PKCS#8** | `-----BEGIN … PRIVATE KEY-----` | `pem` (traditional `DEK-Info`, EVP_BytesToKey) and `pkcs8` **PBES2** (PBKDF2 **or** scrypt) | EVP_BytesToKey / PBKDF2 / scrypt | padding + ASN.1 parse | OpenSSL |
| **JKS (Java KeyStore)** | `0xFEEDFEED` | `jks-sha1` — store-password recovery | — | trailing **SHA-1** integrity digest over the store | `keytool` |
| **PKCS#12** `.p12/.pfx` | ASN.1 `PFX` SEQUENCE | `pkcs12` — password recovery via the PFX `MacData` MAC (independent of the bag encryption) | PKCS#12 KDF (RFC 7292 B.2), **SHA-1 or SHA-256** | the `MacData` HMAC | OpenSSL (modern SHA-256/AES **and** legacy SHA-1/3DES) |
| **PuTTY `.ppk`** | `PuTTY-User-Key-File-` | `putty-v3-argon2id` / `putty-v3-argon2i` (v3) and `putty-v2-sha1` (v2) | v3: **Argon2id / Argon2i**; v2: SHA-1 | the `Private-MAC` after decrypting the private section | `puttygen` |
| **SQLCipher** | *(no magic — target explicitly)* | `sqlcipher4` (PBKDF2-HMAC-**SHA-512** × 256 000) and `sqlcipher3` (PBKDF2-HMAC-**SHA-1** × 64 000) | PBKDF2 → HMAC subkey | the page-1 HMAC | `sqlcipher` CLI |
| **KeePass** `.kdbx` (KDBX4) | `9AA2D903 B54BFB67`, major version 4 | `keepass-kdbx4-argon2d` (default), `-argon2id`, `-aeskdf` | **Argon2d** / Argon2id / legacy AES-KDF | the header **HMAC-SHA256** | `pykeepass`; the in-tree Argon2d is checked against the reference `argon2` CLI |

**SQLCipher** databases have no cleartext magic, so the engine cannot
auto-detect them; force the scheme from the CLI with `xcrack --as sqlcipher FILE`
(or target the scheme via the library API). **KeePass** KDBX **3.x** uses a
different (stream-start-bytes) verifier and is reported unsupported; KDBX4 is the
handled version.

**In-tree Argon2.** KeePass KDBX4 defaults to **Argon2d**, which
`golang.org/x/crypto/argon2` does not expose (only Argon2i/Argon2id). Xcrack
ships its own `xcrypto/prim/argon2` with all three variants; Argon2i/Argon2id
match x/crypto bit-for-bit and Argon2d matches the reference `argon2` CLI's
known-answer vectors (so PuTTY v3 and KeePass both have a vetted Argon2).

---

## Disk images

| Format | Signature | Scheme(s) | KDF | Cipher | Verifier | Oracle |
| ------ | --------- | --------- | --- | ------ | -------- | ------ |
| **Apple encrypted DMG** 🔓 | on-disk `encrcdsa` v2 magic, or a `dmg2john` `$dmg$1*…` / `$dmg$2*…` line | `dmg-v1` (AES-128) and `dmg-v2` (AES-128 / **AES-256**) | PBKDF2-HMAC-SHA1 | v1: 3DES key-unwrap; v2: 3DES-unwrapped AES-CBC | v1: valid PKCS padding on both unwrapped blobs; v2: AES-CBC chunk decrypt yields 8 consecutive NUL bytes (per-chunk IV = HMAC-SHA1(key, chunkNo)) | **real macOS AES-128/256 images** (known password) + **John the Ripper's authoritative `dmg` vectors** (byte-for-byte) |

Xcrack reads a real on-disk **`encrcdsa` v2** image directly — just
`xcrack image.dmg -w wordlist`, with the whole candidate pipeline (spray,
breach, masks, sharding) — and also accepts the portable `$dmg$` line
`dmg2john image.dmg` produces (`dmg2john image.dmg > h` then `xcrack h`). The
on-disk parser follows the dmg2john / vilefault layout and reads only the
header, key blob and one data chunk (via `ReadAt`), never the whole image; it is
**validated against genuine macOS-produced AES-128 and AES-256 images** with a
known password, and the crypto is additionally cross-validated against John's
authoritative `dmg` vectors. The recovered passphrase is the deliverable (the
image is not mounted). Older v1 (`.dmg`, pre-10.5) images are handled via the
`$dmg$` line.

## GPU offload — hash-line export

For schemes where a GPU cracker is faster, `xcrack hashline <file>` probes the
file once and emits the `$…$` hash string hashcat / John the Ripper expect,
instead of searching in-process. These emitters are cross-validated against a
real hashcat (`scripts/hashcat-xval.sh` cracks each emitted line back to the
known password).

| Format | john | hashcat `-m` |
| ------ | ---- | ------------ |
| OOXML Office (2007 / 2010 / 2013) | `office` | 9400 / 9500 / 9600 |
| PDF (R2 / R3–R4 / R5 / R6) | `PDF` | 10400 / 10500 / 10600 / 10700 |
| WinZip AES ZIP entries (128 / 192 / 256) | `ZIP` | 13600 |

A ZIP yields one `$zip2$` line per WinZip-AES entry; because that line carries
the entry's full ciphertext and HMAC-SHA1 tag (which the probe-time report
omits), `hashline` re-reads the entry to build it. Other schemes report that no
emitter exists yet. (ZipCrypto entries are not exported as hash lines — they
have the `kp` known-plaintext path and the external-engine challenge export
instead.)

---

## Not handled (yet) / out of scope

Tracked in [`roadmap-enhancements.md`](roadmap-enhancements.md): BKS key stores,
disk images (ISO/UDF, VHD(X), DMG), installers (MSI/CAB/NSIS/Inno), OneNote /
Outlook mail carriers, Hangul HWP, more codecs (zstd/lz4/brotli/…), and
full-volume encryption (BitLocker, VeraCrypt, LUKS, FileVault).

**Out of scope by design:** in-tree GPU cracking, any online/network attack,
weakening of *sound* ciphers, document rendering or macro execution, and
public-key PDF (which needs a private key, not a password). See
[`asr.md`](asr.md) §5.
