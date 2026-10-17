# How Xcrack attacks each format

This document explains, per supported file type, **how the password or key is
recovered** — the key-derivation function (KDF), the bulk cipher, the *verifier*
(the cheap check that tells a wrong guess from a right one), and which attack the
engine brings to bear. It also catalogues the **verification shortcuts and
cryptographic weaknesses** Xcrack exploits (or could), and which heavy steps the
optional GPU tier accelerates.

For the format **catalogue** (what is detected, parsed and decrypted, with
cross-validation notes) see [`FILEFORMATS.md`](FILEFORMATS.md). For the attack
**backlog** see [`roadmap-enhancements.md`](roadmap-enhancements.md).

> Authorized use only. Xcrack is a recovery/defensive tool: operate on files you
> own or are explicitly permitted to access.

---

## 1. The attack pipeline (all formats)

```
detect  → probe (once)              → verify (per candidate)        → decrypt
magic/    extract salt, iters,         run the KDF, check the          stream the
JSON/     verifier into a Challenge    verifier — the expensive step   plaintext with
header                                                                 the found key
```

Candidates come from the ordered pipeline (highest-yield first):

1. **Cached / recovered passwords** — the found-password cache / potfile and
   ancestor passwords (promotion / `--adaptive`), plus `--loopback` re-mangles.
2. **Default list** — a small built-in common-password list; its first two
   entries are the **empty password** and **`VelvetSweatshop`** (see §3).
3. **Hints & context** — an embedded password hint (iWork `.iwph`, ZIP comment)
   and names / plaintext siblings (`--hint`, `--context`).
4. **Spray / breach / language lists**, then **wordlists** (± rules), then
   **masks / hybrid / combinator / PRINCE / Markov / PCFG** generation.

Every format carries a **cheap verifier** so a wrong guess is rejected without
decrypting the body, and most carry an even cheaper **fast-reject** (a 1–2 byte
check) tried before the KDF. The authoritative verifier is always re-run on a
candidate the fast path or an accelerator flags, so neither can cause a false
positive.

---

## 2. Per-format attack reference

Legend: **KDF** = how a password becomes a key · **verifier** = the pass/fail
check · **attack** = the primary recovery path.

### Archives

| Format | KDF / cipher | Verifier | Attack & shortcuts |
|--------|--------------|----------|--------------------|
| **ZIP — ZipCrypto** | bespoke 32-bit×3 key schedule; PKWARE stream cipher | 1 check byte (1/256), then CRC32 of the content | Dictionary/rules, **a password-free known-plaintext key recovery** (Biham–Kocher), **and cross-entry reuse** — one recovery decrypts the whole archive (`kp --zip`) — see §3. |
| **ZIP — WinZip-AES** (AE-1/2) | PBKDF2-HMAC-SHA1 ×1000; AES-CTR | 2-byte verifier, then HMAC-SHA1 | Dictionary/rules; the PBKDF2 step is GPU-accelerable. Per-entry salt ⇒ no cross-entry key reuse. |
| **7-Zip** (AES-256) | SHA-256 iterated; AES-256-CBC | none cheap — decrypt + CRC | Dictionary/rules; one archive password unlocks all entries. |
| **RAR5** (AES-256) | PBKDF2-HMAC-SHA256 (custom chain); | **8-byte PswCheck in the header — verify with no decrypt** | Dictionary/rules; the fast 8-byte check serves every entry and `-hp` headers. |
| **RAR4** (AES-128) | key schedule; AES-128-CBC | none by design — decrypt + CRC | Dictionary/rules. |

### Microsoft Office

| Format | KDF / cipher | Verifier | Attack & shortcuts |
|--------|--------------|----------|--------------------|
| **Office 97/2000 RC4** | `trunc = MD5(UTF16LE(pw))[:5]`; RC4 | MD5 EncryptionVerifier | Dictionary, **and a direct 40-bit key attack** (`office-keyattack`) — see §3. |
| **Office XP/2003 RC4 CryptoAPI** | SHA-1 → RC4 (per-block rekey) | SHA-1 EncryptionVerifier | Dictionary/rules only — the 160-bit `H0` leaves no 40-bit bottleneck, so no key attack. |
| **Office XOR obfuscation** | 16-byte XOR key array | 16-bit verifier | Passwords crack essentially instantly. |
| **OOXML agile** (2010+) | iterated SHA-1/256/384/512 ×~100k; AES-CBC | hash of a decrypted verifier block | Dictionary/rules; the spin loop is the GPU target. **VelvetSweatshop** for read-only-recommended workbooks (§3). |
| **OOXML standard** (2007) | SHA-1 ×50000; AES-128-ECB | hash of a decrypted verifier block | As above. |

### Documents & media

| Format | KDF / cipher | Verifier | Attack & shortcuts |
|--------|--------------|----------|--------------------|
| **PDF** (RC4 V1–V2, AESV2, AESV3 R5/R6) | MD5 (R2–R4) / SHA-2 "2.B" (R6) | `/U` (user) and, via `/O`, the owner password | Dictionary/rules on user **and** owner password; **owner/permission-only PDFs open with the empty password**; **a direct 40-bit file-key attack** on V1/R2 (and 40-bit R3/R4) RC4 (`pdf-keyattack`) — see §3. |
| **ODF** | PBKDF2-HMAC-SHA1; AES-256-CBC or -GCM | SHA-256 1K checksum (CBC) / GCM tag | Dictionary/rules; PBKDF2 GPU-accelerable. |
| **Apple iWork** | PBKDF2-HMAC-SHA1; AES-128 | `sha256(plain[:32]) == plain[32:64]` | Dictionary/rules; the embedded `.iwph` **hint** is tried first. |
| **Encrypted DMG** (v1/v2) | PBKDF2-HMAC-SHA1; 3DES-unwrap + AES-CBC | double-padding (v1) / 8 NUL bytes (v2) | Dictionary/rules; PBKDF2 GPU-accelerable (high iteration — a prime target). |

### Keys, credential stores & wallets (verify-only; the passphrase is the deliverable)

| Format | KDF | Verifier | Notes |
|--------|-----|----------|-------|
| **OpenSSH key** | bcrypt-pbkdf; AES-CTR | decrypt + key parse | Sound KDF; CPU-only. |
| **PEM / PKCS#8** | EVP_BytesToKey or PBES2 (PBKDF2/scrypt) | PKCS#7 padding + ASN.1 | Legacy MD5-KDF keys are weak/fast. |
| **JKS** | SHA-1(UTF16BE(pw) ‖ "Mighty Aphrodite" ‖ body) | trailing 20-byte digest | Pure-hash verify (no store decrypt). |
| **PKCS#12 (.p12/.pfx)** | RFC 7292 B.2 (SHA-1/256) | MacData HMAC | MAC-only verify, independent of bag encryption. |
| **PuTTY .ppk** | Argon2id/i (v3) or SHA-1 (v2) | Private-MAC | Argon2 is sound; CPU-only. |
| **SQLCipher** (v4/v3) | PBKDF2-HMAC-SHA512 ×256k / -SHA1 ×64k | page-1 HMAC | No AES decrypt to verify; SHA-512 PBKDF2 is GPU-accelerable. |
| **KeePass KDBX4** | Argon2d/id or AES-KDF | header HMAC-SHA256 | Argon2 is memory-hard; CPU-only. |
| **KeePass KDBX3.1** | AES-KDF (AES-256-ECB rounds) | stream-start bytes (AES-CBC) | AES-KDF is GPU-accelerable (shared seed). |
| **Ethereum keystore v3** | scrypt or PBKDF2-HMAC-SHA256 | Keccak-256 MAC | scrypt is memory-hard; PBKDF2 variant is GPU-accelerable. |
| **age (passphrase)** | scrypt; ChaCha20-Poly1305 | stanza AEAD tag | scrypt memory-hard; CPU-only. Public-key age needs a private key (out of scope). |
| **OpenPGP symmetric** (`gpg -c`) | S2K (iterated-salted) | 2-byte CFB quick-check, then SHA-1 MDC | S2K is a cheap iterated hash; GPU-accelerable (multi-block). |

### Data stores

| Format | Status |
|--------|--------|
| **MS Access — Jet** (.mdb, Access 97–2003) | Password recovered directly from the header XOR obfuscation — **no cracking** (`xcrack access-recover`), see §3. |
| **MS Access — ACE** (.accdb, Access 2007+) | Detection/identification only; the Office-style RC4/AES KDF has no shortcut, so a password search is the only route. |

---

## 3. Verification shortcuts & cryptanalysis

Xcrack prefers a shortcut over brute force wherever a real one exists. These
bypass or shrink the search:

### Already implemented

- **ZipCrypto known-plaintext key recovery (Biham–Kocher).** ZipCrypto is
  cryptographically broken: given ~12+ known plaintext bytes of any entry,
  `xcrack kp` (and the engine's per-entry `KeyRecover`) recover the 96-bit
  internal key state with **no password**, then optionally the password itself.
  Implemented in-tree (`xcrypto/scheme/zipcrypto`) with an external bkcrack
  offload (`--bkcrack`); results are CRC-re-validated, so a wrong known-plaintext
  cannot false-positive.
- **ZipCrypto cross-entry key reuse.** Every entry in a ZipCrypto archive shares
  one password and hence one pre-header key state, so a single recovery unlocks
  the whole archive. Once `xcrack kp --decrypt` has recovered that state (from a
  known-plaintext key recovery *or* a found password), `--zip ARCHIVE` seeds it
  into every other entry and decrypts them all with **no further search**
  (`--zip-out DIR` writes them out). Each entry is independently CRC-re-validated
  (`zip.DecryptArchiveWithStart`); AES and non-ZipCrypto entries are skipped.
- **Office 97/2000 40-bit RC4 key attack ("Thunder Tables").** The password
  enters only as `trunc = MD5(UTF16LE(pw))[:5]` — 40 bits — and the verifier and
  every block key derive from `trunc` and the salt alone. `xcrack office-keyattack`
  sweeps the 2^40 trunc space against the verifier and recovers the document key
  regardless of password length/complexity. Shardable and GPU-friendly.
- **PDF 40-bit RC4 key attack (V1/R2, and 40-bit R3/R4).** The PDF file key is a
  single MD5 truncated to 5 bytes — 40 bits — independent of the password's
  length, and the `/U` verifier, every per-object key and the whole document are
  functions of that file key alone. `xcrack pdf-keyattack` sweeps the 2^40
  file-key space against `/U` and recovers the key with no password, using only
  the public `/U`, `/ID` and revision (not `/O`, `/P`, or the password). The
  common R2 case runs an allocation-free inline-RC4 hot loop; shardable
  (`--shard i/N`) and parallel (`--workers`). 128-bit RC4 and the AES schemes
  (AESV2/AESV3) have no such bottleneck and the command declines them. Validated
  against a real 40-bit PDF produced by qpdf (`keyattack_test.go`).
- **MS Access (Jet) header XOR.** Jet3/Jet4 store the database password
  XOR-obfuscated with fixed, public material — the header page is masked with a
  fixed 128-byte mask, and (Jet4 only) the password field is additionally masked
  with a 4-byte value folded from the creation date. `xcrack access-recover`
  reverses both and reads the password straight out of the header with **no
  cracking** (`xfileformats/formats/access.RecoverJetPassword`). ACE (.accdb,
  Access 2007+) uses a real Office-style KDF and is declined. Cross-validated
  against jackcess (an independent implementation that produced a known-password
  Jet4 fixture; `jet_test.go`), with the decoder fuzzed against hostile headers.
- **VelvetSweatshop / empty password.** Excel "encrypts" a read-only-recommended
  workbook with the fixed key `VelvetSweatshop`; owner/permission-only PDFs and
  read-only Office documents open with the **empty** password. Both are the first
  two built-in default candidates, so these files unlock with zero real search.
- **Embedded hints.** The iWork `.iwph` hint and ZIP entry comments are parsed
  and tried first (`--hint`), and plaintext siblings that name the password are
  harvested (`--context`).
- **Fast verifiers.** RAR5's 8-byte header check, the ZipCrypto check byte, the
  WinZip-AES 2-byte value, and the OpenPGP 2-byte CFB quick-check reject most
  wrong guesses before the KDF runs.

### Known, real, and staged (documented, not yet implemented)

Nothing is currently staged here — the three weaknesses that were staged in the
previous cycle (ZipCrypto cross-entry reuse, PDF 40-bit RC4, and MS Access Jet
header XOR) are all implemented and listed above, each cross-validated against
an external oracle. ACE (.accdb, Access 2007+) is the one Access variant without
a shortcut: its Office-style RC4/AES KDF leaves only a password search, so it is
identified but not key-attacked.

### Judged not worth it / not applicable (and why)

- **JKS per-key keystream known-plaintext (Ettlinger).** Real, but it recovers
  the per-key *key-protection* password / the key itself, not the store integrity
  password Xcrack delivers (and the store and key passwords are usually identical
  anyway, so the recovered store password typically is the key password).
- **Weak-MAC / public-material cross-checks** (PKCS#12, PEM-with-certificate):
  no speedup — the existing verifiers already have a ~2^-32…2^-160 false-positive
  rate.
- **Public-key age / PGP, full RAR4/7z verifiers:** no shortcut exists (need a
  private key, or the format stores no verifier by design).

---

## 4. What the GPU tier accelerates (and what it can't)

The opt-in OpenCL tier (`xcrackd --gpu`, `-tags opencl`) batches the one heavy,
embarrassingly-parallel step — the KDF — and leaves verification on the CPU. It
ships **PBKDF2-HMAC-SHA1 / -SHA256 / -SHA512** kernels today, each byte-for-byte
self-tested against the Go reference before use.

**Good candidates for additional kernels** (catalogued from a survey of the
schemes):

| Candidate | Benefits | Difficulty |
|-----------|----------|------------|
| **Office agile iterated hash** (SHA-1/256/384/512 spin, ~100k) | every Office 2010+ doc | easy–moderate; reuses the SHA cores, single-block per iteration |
| **Office standard iterated hash** (SHA-1 ×50000) | Office 2007 | easy; SHA-1 case of the above |
| **Office 97/2000 2^40 trunc sweep** (MD5 + RC4) | every 97/2000 doc; collapses the dominant attack cost | moderate; needs MD5 + RC4 cores |
| **RAR5 check-value chain** | every RAR5 archive | trivial — it **is** PBKDF2-HMAC-SHA256(iter+32) folded to 8 bytes; only a format-layer `AccelKDF` is needed |
| **KeePass AES-KDF** (KDBX3 / KDBX4 AES) | KeePass AES-KDF files | moderate; needs an AES-256 core; the seed is shared across candidates |
| **PDF R2–R4 MD5+RC4** | PDF dictionaries | low once MD5+RC4 cores exist |

**Deliberately CPU-only / out of scope for a kernel:** Argon2 (KeePass/PuTTY) and
scrypt (Ethereum/age/PBES2) are **memory-hard** — each work-item needs its whole
memory region, so a GPU runs only a few hundred concurrent instances; bcrypt
(OpenSSH) is Blowfish-based and GPU-hostile; and the ZipCrypto Biham–Kocher search
is branch-divergent cryptanalysis best served by the existing external bkcrack
offload.

Native **ROCm/HIP** (AMD) and CUDA back-ends are a documented future; because the
kernels are vendor-neutral OpenCL C, AMD GPUs and Ryzen APUs already run them
through the OpenCL ICD, and the tier auto-selects the best device across vendors
(see [`roadmap-enhancements.md`](roadmap-enhancements.md) §3).
