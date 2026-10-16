# Xcrack — Enhancement Roadmap

A living, tracked backlog of features and attacks beyond the delivered format
set. The high-level phased plan lives in [`roadmap.md`](roadmap.md); this file
is the detailed, checkbox-level tracker.

**Status legend:** ✅ done · 🚧 in progress · ⬜ planned · 🔬 research / large

Items marked **[batch]** are the current implementation batch.

---

## 1. Basic features (table-stakes)

| | Feature | Notes |
|--|---------|-------|
| ✅ | **ASCII-armored input** | age armor and OpenPGP armor (base64 + CRC-24) are de-armored transparently in `Parse`; both formats detect armored input. Cross-validated against `age -a` / `gpg -a`. |
| ✅ | **Mask length incrementing** | `pattern.ExpandIncrement(mask, min, max)` expands a mask over a length range (CLI wiring pending). |
| ✅ | **Live progress / rate / ETA (CLI)** | `--progress`: files done/total, candidates, rate, elapsed, file-rate ETA to stderr (per-file granularity). |
| ✅ | **Potfile** | `--potfile`: recovered passwords load as high-priority candidates (tried first everywhere) and new ones are appended — crack once, instant next time. |
| ✅ | **Structured logging** | `Options.Logger` backed by `log/slog`; `--log-level`; never logs secrets. |
| ✅ | **Single-password ergonomics** | `--password-file` (lines) and `--password-env VAR` keep a secret off the command line. |
| ✅ | **Find-all** | `--find-all` → `Options.FindAll`; the tree is always fully explored (every encrypted node searched/reported independently). |

## 2. Intermediate features

| | Feature | Notes |
|--|---------|-------|
| ✅ | **Checkpoint / resume** | `candidates.Checkpoint` + CLI `--checkpoint FILE`: persists the search position (with a keyspace signature) every N candidates and atomically; an interrupted single-target run resumes a safety margin behind the saved point so no in-flight candidate is skipped. Non-cloneable (single global cursor) and seeks only on the first `Reset`, so a multi-entry container never cascade-skips; scoped to single-target runs (guarded in the CLI). |
| ✅ | **Full rule engine** | Broad hashcat function set (case, dup/reflect, rotate/trim, insert/overwrite/swap/extract, ascii±, title, `pN zN ZN yN YN`, …) + reject rules (`<>_ ! / ( ) =`) + stacking; word length capped (bomb-safe). |
| ✅ | **Context / association candidates** | `--context` / `Options.ContextCandidates`: seeds each search with guesses derived from the file/entry name (stem, tokens, digit runs) and plaintext harvested from plain sibling entries (a README or email body that names the password). Tried after promotion, before the general keyspace. Parsers fuzzed (no-panic). |
| ✅ | **Per-format fast-reject** | `Options.FastReject(path, candidate) bool`: a cheap caller pre-check consulted before the expensive KDF for every generated candidate (never for proven promoted passwords); returning true prunes a hopeless keyspace without a false-positive risk. Built-in verifiers already carry their own fast verifier checks (ZipCrypto check byte, WinZip-AES 2-byte, OpenPGP CFB quick-check). |
| ✅ | **Candidate dedup** | `candidates.Dedup` — bounded dedup wrapper so masks×rules don't retry a string. |
| 🚧 | **Streaming large inputs** | Reads are already bounded (`MaxEntrySize`/`MaxTotalBytes`, `io.SectionReader`), so a malicious or huge input cannot exhaust memory. Fully *streaming* decrypt/decompress of large entries without materializing each one (bounded sliding windows through the container readers) is a larger architectural change, staged. |
| ✅ | **Prometheus-format metrics** | `Metrics.WritePrometheus` + `GET /metrics` text exposition (alongside JSON `/v1/metrics`). |
| ✅ | **Combinator attack** | `candidates.Combinator(left, right, sep)` (CLI wiring pending). |
| ⬜ | **Hybrid attack** | wordlist ± mask (dict+mask / mask+dict). |
| ⬜ | `*2john` / hashcat hash-line emitters | Per-scheme `$…$` strings to complete the external-GPU bridge. |

## 3. Advanced features

| | Feature | Notes |
|--|---------|-------|
| ✅ | **Observability** | `Options.OnAudit` emits a secrets-free `AuditEvent` per node (path, format, status, encrypted, size) for an audit log or trace. |
| 🚧 | **Markov / PCFG generators** | ✅ Markov generator (`candidates.MarkovGen`, best-first) covers statistical generation today. A full PCFG (Weir et al. — learn a probabilistic context-free grammar of structure/segments and enumerate by probability) is a distinct, larger model, staged. |
| 🔬 | Distributed cracking | Keyspace sharding across a coordinator + workers. |
| 🔬 | GPU/OpenCL offload (external) | Out of tree; reached via the hash-line bridge above. |
| 🔬 | Adaptive scheduling | Order files/candidates by observed crackability; corpus-wide promotion. |
| 🔬 | Breach-corpus / spray sources | HIBP-style and org leak lists as first-class candidate sources. |

## 4. Cracking approaches

| | Approach | Notes |
|--|----------|-------|
| ✅ | Dictionary / wordlist | Implemented. |
| ✅ | Mask brute-force | Implemented (`?l?u?d?s?a?b` + `?1..?4`). |
| ✅ | Rule mangling (full) | Broad hashcat function set + reject rules + stacking. |
| ✅ | Password promotion | Implemented. |
| ✅ | Statistical **ordering** (Markov) | `candidates.ByScore` + `Markov`. |
| ✅ | **Combinator** | `candidates.Combinator`. |
| ✅ | **Markov/PCFG generation** | Markov ✅ (`MarkovGen`); PCFG ✅ (`candidates.TrainPCFG` + `--pcfg`) — Weir-style grammar, guesses emitted in probability order via the pre-terminal priority-queue enumeration (pivot-deduped). |
| ✅ | **Known-plaintext attack on ZipCrypto** | Full Biham–Kocher key recovery (bkcrack-style), implemented from the algorithm with this package's own verified primitives — no third-party code. `RecoverKeys(plain, cipher)` recovers the 96-bit internal state with **no password and no external reducer**: a keystream-only *Zreduction* of the key2 candidates (`reduceKey2`), full key2-window reconstruction (`exploreZ`), a fiber-accelerated key1 enumeration, and the verified key0 reconstruction + full re-encryption check. Correctness is proven end-to-end (`TestAutoPipelineRecovers`); the primitives are unit-tested as exact inverses. **Performance:** compute-heavy in pure Go — the keystream leaves ~10⁵ key2 candidates and the per-candidate key1 enumeration is ~2¹⁶. A two-step *fiber* roll-back (`msbProdFiber2`) pins the key0 low byte to ~2 candidates at **every** level, so the per-window cost is ~2¹⁶ `buildAndVerify` calls rather than ~2²⁴ (a ~34× per-window speedup, measured by `BenchmarkPerWindow`); a full search is then minutes across cores rather than hours (optimized C++ like bkcrack is a small constant factor faster still). `RecoverKeysBudget` bounds the effort; `RecoverKeysWith` + `ExternalBkcrack{Bin}` (CLI `--bkcrack`) offloads to a local bkcrack binary, and the key2 sequence can also be offloaded to an external engine via the challenge-export bridge. ZipCrypto is cryptographically broken, so this is legitimate cryptanalysis (not weakening a sound cipher). |
| 🔬 | Hybrid, PRINCE, toggle/keyboard-walk | Additional generators. |

## 5. Application file formats

Implemented: ZIP (ZipCrypto/WinZip-AES), tar/gzip/bzip2/xz, 7z & RAR (incl.
header-encrypted), OOXML, legacy MS Office (.doc/.xls/.ppt), PDF, ODF, MIME
(.eml), age, symmetric OpenPGP, OpenSSH private keys, encrypted PEM/PKCS#8 keys.

| | Format(s) | Notes |
|--|-----------|-------|
| ✅ | **OpenSSH private keys** | bcrypt-pbkdf + aes-ctr; verified via x/crypto/ssh, cross-checked against ssh-keygen. |
| ✅ | **Encrypted PEM / PKCS#8 keys** | Traditional DEK-Info (EVP_BytesToKey) and PBES2 (PBKDF2 / scrypt + AES-CBC); cross-checked against OpenSSL. |
| ✅ | **JKS (Java KeyStore)** | Store-password recovery via the trailing SHA-1 integrity digest; cross-checked against keytool. |
| ✅ | **PKCS#12 (.p12/.pfx)** | Password recovery via the PFX MacData MAC (PKCS#12 KDF, RFC 7292 B.2 + HMAC); algorithm-independent of the bag encryption, cross-checked against OpenSSL (modern SHA-256/AES and legacy SHA-1/3DES). |
| ✅ | **PuTTY `.ppk`** | v3 (Argon2id/i) and v2 (legacy SHA-1); passphrase verified by the Private-MAC after decrypting the private section; cross-checked against puttygen. |
| ⬜ | BKS, Argon2d-based KDBX | Remaining key stores (KDBX needs in-tree Argon2d). |
| ⬜ | Disk images: ISO/UDF, VHD(X), IMG | Dominant malware-delivery containers (unpack, not always crypto). |
| ⬜ | MSI, CAB, SFX, NSIS/Inno installers | Common lures; unpack. |
| ⬜ | OneNote `.one`, Outlook `.msg` / PST / MBOX | Mail/notes carriers. |
| ✅ | **SQLCipher** | Passphrase recovery via the page-1 HMAC (PBKDF2 → HMAC subkey → HMAC-SHA512/SHA1 over page 1), SQLCipher v4 and v3 profiles; cross-checked against the sqlcipher CLI. Library-only (`xcrypto/scheme/sqlcipher`) — SQLCipher files have no cleartext magic, so a caller must target them explicitly (not engine-autodetected). |
| 🔬 | KeePass `.kdbx` | KDBX4's default KDF is **Argon2d**, which `golang.org/x/crypto` does not expose (only Argon2i/id); needs an in-tree Argon2d. The MAC-based verifier is otherwise ready. Staged. |
| ⬜ | Apple iWork, ODF AES-GCM, Hangul HWP | Document suites. |
| 🔬 | Full-volume: BitLocker, VeraCrypt, LUKS, FileVault | Large, separate effort + threat review. |
| ⬜ | More codecs: zstd, lz4, brotli, LZH, ARJ, ACE, SecureZIP | Archive breadth. |

## Out of scope (non-goals)

In-tree GPU cracking · any online/network attack · weakening of **sound**
ciphers · document rendering / macro execution · public-key PDF (needs a
private key, not a password). See [`asr.md`](asr.md) §5.
