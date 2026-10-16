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
| ⬜ | **Checkpoint / resume** **[batch]** | Persist search position for a long single-file run; resume after interruption. |
| ✅ | **Full rule engine** | Broad hashcat function set (case, dup/reflect, rotate/trim, insert/overwrite/swap/extract, ascii±, title, `pN zN ZN yN YN`, …) + reject rules (`<>_ ! / ( ) =`) + stacking; word length capped (bomb-safe). |
| ✅ | **Context / association candidates** | `--context` / `Options.ContextCandidates`: seeds each search with guesses derived from the file/entry name (stem, tokens, digit runs) and plaintext harvested from plain sibling entries (a README or email body that names the password). Tried after promotion, before the general keyspace. Parsers fuzzed (no-panic). |
| ✅ | **Per-format fast-reject** | `Options.FastReject(path, candidate) bool`: a cheap caller pre-check consulted before the expensive KDF for every generated candidate (never for proven promoted passwords); returning true prunes a hopeless keyspace without a false-positive risk. Built-in verifiers already carry their own fast verifier checks (ZipCrypto check byte, WinZip-AES 2-byte, OpenPGP CFB quick-check). |
| ✅ | **Candidate dedup** | `candidates.Dedup` — bounded dedup wrapper so masks×rules don't retry a string. |
| ⬜ | **Streaming large inputs** **[batch]** | Avoid materializing whole archives; stream bounded windows. |
| ✅ | **Prometheus-format metrics** | `Metrics.WritePrometheus` + `GET /metrics` text exposition (alongside JSON `/v1/metrics`). |
| ✅ | **Combinator attack** | `candidates.Combinator(left, right, sep)` (CLI wiring pending). |
| ⬜ | **Hybrid attack** | wordlist ± mask (dict+mask / mask+dict). |
| ⬜ | `*2john` / hashcat hash-line emitters | Per-scheme `$…$` strings to complete the external-GPU bridge. |

## 3. Advanced features

| | Feature | Notes |
|--|---------|-------|
| ✅ | **Observability** | `Options.OnAudit` emits a secrets-free `AuditEvent` per node (path, format, status, encrypted, size) for an audit log or trace. |
| 🚧 | **Markov / PCFG generators** | ✅ Markov generator (`candidates.MarkovGen`, best-first); PCFG/OMEN still 🔬. |
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
| 🚧 | **Markov/PCFG generation** | Markov ✅ (`MarkovGen`); PCFG planned. |
| 🚧 | **Known-plaintext attack on ZipCrypto** | Biham–Kocher key recovery (bkcrack-style): recover the 96-bit internal state from known plaintext, no password. ZipCrypto is cryptographically broken, so this is legitimate cryptanalysis (not weakening a sound cipher). **Shipped & verified** (`xcrypto/scheme/zipcrypto`): the exact cipher-inverse primitives (crc32 inverse, mult inverse, keystream↔key2 table — unit-tested as exact inverses); `RecoverInternalState(key2Seq, plain)` — reconstructs the full state from the key2 sequence over the window + the known plaintext (round-trip validated); `Keys.RollBack` — rolls a recovered state back across the header, recovering it. **Staged (front half):** the keystream-only *Zreduction* of the key2 sequence + the fiber-table key1/key0 search — a naive enumeration over-generates astronomically, so an efficient, separately-verifiable reduction is still to land; until then the key2 sequence comes from an external reducer (e.g. a GPU/bkcrack worker via the challenge-export bridge). |
| 🔬 | Hybrid, PRINCE, toggle/keyboard-walk | Additional generators. |

## 5. Application file formats

Implemented: ZIP (ZipCrypto/WinZip-AES), tar/gzip/bzip2/xz, 7z & RAR (incl.
header-encrypted), OOXML, legacy MS Office (.doc/.xls/.ppt), PDF, ODF, MIME
(.eml), age, symmetric OpenPGP.

| | Format(s) | Notes |
|--|-----------|-------|
| ⬜ | Disk images: ISO/UDF, VHD(X), IMG | Dominant malware-delivery containers (unpack, not always crypto). |
| ⬜ | MSI, CAB, SFX, NSIS/Inno installers | Common lures; unpack. |
| ⬜ | OneNote `.one`, Outlook `.msg` / PST / MBOX | Mail/notes carriers. |
| ⬜ | Key stores: SSH private keys, PuTTY `.ppk`, PEM, PKCS#8/#12, JKS/BKS | Classic crack targets. |
| ⬜ | KeePass `.kdbx`, SQLCipher | Staged pending test fixtures. |
| ⬜ | Apple iWork, ODF AES-GCM, Hangul HWP | Document suites. |
| 🔬 | Full-volume: BitLocker, VeraCrypt, LUKS, FileVault | Large, separate effort + threat review. |
| ⬜ | More codecs: zstd, lz4, brotli, LZH, ARJ, ACE, SecureZIP | Archive breadth. |

## Out of scope (non-goals)

In-tree GPU cracking · any online/network attack · weakening of **sound**
ciphers · document rendering / macro execution · public-key PDF (needs a
private key, not a password). See [`asr.md`](asr.md) §5.
