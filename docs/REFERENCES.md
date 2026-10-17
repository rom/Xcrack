# Xcrack — References

A commented map of the cryptography, cryptanalysis, candidate-generation and
attack-orchestration methods Xcrack implements, with primary references and a
note on how (and where) each is used. It doubles as a reading list for anyone
extending the tool.

Everything here is used for **offline** password recovery against a file's own
key-derivation function — Xcrack never attacks remote systems and never weakens
a sound cipher.

---

## 1. Key-derivation functions (KDFs)

The KDF is what makes a guess expensive; it is the single biggest factor in
attack speed. Xcrack reads the KDF parameters (salt, iteration/cost, output
length) from each file rather than assuming them.

| KDF | Reference | Used by / notes |
| --- | --------- | --------------- |
| **PBKDF2** (HMAC-SHA1 / -SHA256 / -SHA512) | RFC 8018 (PKCS #5 v2.1), RFC 2104 (HMAC) | WinZip-AES (SHA1, 1000), DMG (SHA1), ODF (SHA1), SQLCipher (SHA1/SHA512), PDF, RAR5 (SHA256), Office agile. `xcrypto/prim.PBKDF2`. The GPU tier accelerates the SHA1 variant. |
| **Argon2** (d / i / id) | RFC 9106 | KeePass KDBX4 (Argon2d is the default and is **not** in `x/crypto`, so Xcrack ships its own `xcrypto/prim/argon2`, cross-validated against the `argon2` CLI). |
| **scrypt** | RFC 7914 | `age` scrypt-passphrase recipient; PEM/PKCS#8 PBES2-scrypt. |
| **bcrypt-pbkdf** | OpenBSD; Provos & Mazières, "A Future-Adaptable Password Scheme" (1999) | OpenSSH private keys. |
| **EVP_BytesToKey** (MD5) | OpenSSL | Traditional DEK-Info PEM keys. |
| **Office "spin" hash** | [MS-OFFCRYPTO] §2.3.4.* | Legacy RC4 CryptoAPI (SHA1), agile (configurable hash, 100k), standard (SHA1, 50k). `xcrypto/scheme/officebinary`, `ooxml`. |
| **RAR4 KDF** | RARLAB; unrar | SHA1, 2¹⁸ rounds, derives AES-128 key + IV. No verification value (see §3). |
| **RAR5 KDF** | RARLAB RAR 5.0 format; unrar `crypt5.cpp` | PBKDF2-HMAC-SHA256, iteration count stored as a base-2 log in the header (default 2¹⁵). `xcrypto/scheme/rar5`. |
| **PKCS#12 KDF** | RFC 7292 App. B | `.p12/.pfx` MacData MAC. |
| **PKCS#12 v2 / RC4 CryptoAPI** | [MS-OFFCRYPTO] | legacy Office. |

## 2. Ciphers and modes

| Primitive | Reference | Used by |
| --------- | --------- | ------- |
| **AES** | FIPS 197 | nearly everything modern |
| AES-CBC / CTR / ECB | NIST SP 800-38A | DMG, RAR, ODF-CBC, Office, WinZip-AES (CTR, little-endian counter) |
| AES-GCM | NIST SP 800-38D | ODF 1.3; the auth tag is a fail-safe verifier |
| **RC4** | — ([MS-OFFCRYPTO] for the Office profiles) | legacy Office 97/2000 & RC4 CryptoAPI, PDF RC4 |
| **3DES (EDE)** + RFC 3217 key-wrap | NIST SP 800-67; RFC 3217 | DMG v1/v2 key-blob unwrap |
| **ChaCha20-Poly1305** | RFC 8439 | `age`, OpenPGP (where used) |
| **ZipCrypto** (PKWARE stream cipher) | PKWARE APPNOTE §6 | traditional ZIP encryption — cryptographically broken (see §4) |

## 3. Verification shortcuts (fast reject)

A format that stores a **password-verification value** lets a wrong password be
rejected cheaply — after the KDF alone, with no bulk decryption. Exploiting
these is the difference between a fixed, quotable cost per candidate and "it
depends on the file size" (see the RAR reference in §7). Xcrack uses the
authoritative verifier for every scheme, and `Options.FastReject` adds a
caller-supplied cheap pre-check.

| Scheme | Verifier |
| ------ | -------- |
| WinZip-AES | 2-byte password-verification value, then HMAC-SHA1 over the ciphertext |
| **RAR5** | 8-byte check value in the header (`xcrypto/scheme/rar5`) — verify without decrypt |
| RAR4 | **none** — must decrypt + decompress + CRC32, so cost scales with the archive |
| PKCS#12 | MacData HMAC (RFC 7292 B.2) |
| JKS | trailing SHA-1 integrity digest |
| KeePass KDBX4 | header HMAC-SHA256 |
| SQLCipher | page-1 HMAC (SHA1/SHA512) |
| ODF | 1K checksum (CBC) or the GCM auth tag |
| ZipCrypto | 1-byte check byte from the 12-byte encryption header |
| Office | the EncryptionVerifier (hash of a decrypted random block) |

## 4. Cryptanalysis

- **ZipCrypto known-plaintext (Biham–Kocher).** Eli Biham & Paul C. Kocher, *A
  Known Plaintext Attack on the PKZIP Stream Cipher* (FSE 1994). Recovers the
  96-bit internal key state from a few known plaintext bytes — no password.
  Xcrack implements it in-tree (`xcrypto/scheme/zipcrypto`) with a two-step
  *fiber* roll-back (~34× faster key1 search) and can offload to the reference
  implementation, **bkcrack** by Kévin Falcoz
  (<https://github.com/kimci86/bkcrack>), re-validating whatever it returns.
  This is legitimate cryptanalysis of a weak-by-design cipher.

## 5. Candidate generation and ordering

Reducing the number of guesses matters more than raw speed against strong KDFs
(see §7). Xcrack's sources, roughly in try-first order:

| Method | Reference / origin | Xcrack |
| ------ | ------------------ | ------ |
| Dictionary / wordlist | — | `candidates.File`, `Chain` (dedups across sources) |
| Common-password & breach lists | SecLists; Mark Burnett "Top 10000"; HIBP counts | `--breach`, built-in default list, `--swedish` |
| Password spraying | — | `--spray` (common + org/season/year) |
| Rule mangling | hashcat rules engine | `xcrypto/pattern` (full function + reject set) |
| Masks + increment | hashcat masks / `--increment` | `pattern` masks, `--increment MIN:MAX` |
| Combinator | hashcat `-a 1` | `--combinator-left/-right/-sep` |
| Hybrid (dict ± mask) | hashcat `-a 6/7` | `--hybrid-append/-prepend` |
| Toggle-case / keyboard-walk / PRINCE | hashcat; PRINCE by Jens Steube | `--toggle-case`, `--keyboard-walk`, `--prince` |
| **Markov** ordering & generation | Narayanan & Shmatikov, *Fast Dictionary Attacks … Time-Space Tradeoff* (CCS 2005) | `--order markov` (reorder), `--markov` (generate) |
| **PCFG** | Weir, Aggarwal, de Medeiros, Glodek, *Password Cracking Using Probabilistic Context-Free Grammars* (IEEE S&P 2009) | `--pcfg` |
| Context / association | — | `--context` (names + plaintext siblings) |
| Embedded hints | — | `--hint`, `--hint-rules` |

**Dictionary craft** (from the Elcomsoft "A Word About Dictionaries" post, §7):
frequency-sort leaked-password lists; length-sort natural-language lists when
mutating; deduplicate; a ~10k-entry language-specific list plus light mutations
is the sweet spot. The bundled Swedish list (`gen_swedish.go`) is built this
way.

## 6. Attack orchestration

- **Password-recovery queue.** An ordered list of (file, attack) jobs. Two
  workflows — weakest-protected file first, or fastest/shortest attack first —
  and a format-strength table to prioritise (see §7, the queue post). Xcrack
  realises this as: the candidate-source order (fast lists → mutations →
  masks/brute force), `--adaptive` (corpus-wide promotion + smallest-first
  dispatch), and the distributed allocation modes below.
- **Keyspace sharding.** A disjoint 1/N stride per worker (`--shard I/N`,
  `candidates.Shard`), composable with the challenge envelope.
- **Challenge export/import.** A portable JSON envelope (`xcrypto.ExportChallenge`
  / `UnmarshalChallenge`) so probing and heavy cracking can be split across
  processes/machines; `xcrack export-challenge` / `--resume-from`.
- **Distributed cluster.** `pkg/cluster` fans candidate batches out to many
  `xcrackd` workers — collective (one file, many servers) or partition (server
  groups on different files).
- **GPU/OpenCL offload.** Out-of-tree via the hash-line bridge (hashcat / John),
  and the opt-in in-tree `xcrackd` tier that batches PBKDF2-HMAC-SHA1 onto a
  device (`pkg/accel`, `-tags opencl`).
- **Hash-line emitters.** `$office$`, `$pdf$`, `$zip2$`, `$dmg$`
  (`xcrack hashline`) for hashcat (`-m`) / John.

## 7. Industry references — Elcomsoft blog

These posts informed the design; each is data to weigh, not instructions. Dates
and titles as published. What Xcrack took from each:

- **The RAR Mystery: Breaking RAR4 and RAR5 Encryption** (2026-07) —
  <https://blog.elcomsoft.com/2026/07/the-rar-mystery-breaking-rar4-and-rar5-encryption/>.
  RAR5 stores an 8-byte check value and its PBKDF2-HMAC-SHA256 iteration count
  in the header (default 2¹⁵, *read it, don't assume*); RAR4 stores no verifier,
  so its cost scales with the archive. **Applied:** `xcrypto/scheme/rar5` +
  the format-layer crypt-record parser give RAR5 verify-without-decrypt, and the
  iteration count is read per-archive.
- **Building a Password Recovery Queue** (2023-03) —
  <https://blog.elcomsoft.com/2023/03/building-a-password-recovery-queue/>.
  Order (file, attack) jobs weakest-first or fastest-first; use a format-strength
  table (WinZip AES-256 = 1; NTLM ~45000× faster; RAR5 ~10× slower). **Applied:**
  candidate-source ordering, `--adaptive`, the distributed allocation modes, and
  `--time-limit` for bounded "short attacks first".
- **A Word About Dictionaries** (2023-03) —
  <https://blog.elcomsoft.com/2023/03/a-word-about-dictionaries/>. Dictionary
  optimisation: frequency vs length sort, dedup, lowercase for mutation,
  language-specific lists, ~10k sweet spot, generic mutations. **Applied:** the
  Swedish list design and `--order markov` / `Chain` dedup.
- **How to Break 30% of Passwords in Seconds** (2017-02) —
  <https://blog.elcomsoft.com/2017/02/how-to-break-30-per-cent-of-passwords-in-seconds/>.
  ~30% of passwords are in the Top-10000; try common lists first, then append
  digits. **Applied:** the default list / `--breach` / `--spray` tried ahead of
  bulk wordlists, with rule-mangled digit suffixes.
- **How to Break 70% of Passwords in Minutes** (2017-02) —
  <https://blog.elcomsoft.com/2017/02/how-to-break-70-of-passwords-in-minutes/>.
  ~60% of users reuse passwords; a custom dictionary of a user's *other*
  passwords + light mutations breaks ~70%. **Applied:** `--adaptive` (corpus-wide
  promotion), the potfile, and `--context` reuse harvested passwords across a
  corpus and nested layers.
- **Microsoft Office encryption evolution: from Office 97 to Office 2019**
  (2019-10) —
  <https://blog.elcomsoft.com/2019/10/microsoft-office-encryption-evolution-from-office-97-to-office-2019/>.
  Per-version algorithms and relative crackability: 97/2000 RC4-MD5-40bit (fast),
  XP/2003 default same, 2007 AES-128 + 50k SHA-1, 2010 100k SHA-1, 2013+ AES-256
  + 100k SHA-512 (slow — dictionary attacks only). **Confirms** Xcrack's
  per-version implementations and informs the queue strength ordering.

## 8. Format & standard specifications

- [MS-OFFCRYPTO] — Microsoft Office document encryption (RC4, CryptoAPI, agile, standard).
- ISO 32000-1 / ISO 32000-2 — PDF, incl. the Adobe-extension Algorithm 2.B (AES-256 / R6).
- PKWARE `.ZIP` APPNOTE — ZIP, ZipCrypto, WinZip-AES extra field 0x9901.
- RARLAB RAR 5.0 archive format; unrar source (`crypt5.cpp`) — RAR5 crypt record.
- Apple `encrcdsa` / vilefault — encrypted DMG (Appelbaum & Weinmann); `dmg2john` (John the Ripper).
- age specification (age-encryption.org/v1) — scrypt recipient.
- KeePass KDBX 4 format; SQLCipher design documentation.
- RFCs: 2104 (HMAC), 2898/8018 (PBKDF2/PKCS#5), 7292 (PKCS#12), 7914 (scrypt),
  8439 (ChaCha20-Poly1305), 9106 (Argon2), 3217 (3DES key wrap), 5208 (PKCS#8).
