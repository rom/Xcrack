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
| ⬜ | **ASCII-armored input** **[batch]** | Decode age armor (`-----BEGIN AGE ENCRYPTED FILE-----`) and OpenPGP armor (`-----BEGIN PGP MESSAGE-----`, base64 + CRC-24) before parsing. |
| ⬜ | **Mask length incrementing** **[batch]** | `--increment[-min/-max]`: expand a mask over a length range. |
| ⬜ | **Live progress / rate / ETA (CLI)** **[batch]** | Opt-in `--progress`; candidates/sec and keyspace ETA to stderr via the existing `OnProgress` hook. |
| ⬜ | **Potfile** **[batch]** | Record `digest → password`; skip already-cracked inputs (`--potfile`). |
| ⬜ | **Structured logging** **[batch]** | Wire `Options.Logger` to `log/slog`; `--log-level`; never logs secrets. |
| ⬜ | **Single-password ergonomics** **[batch]** | `--password-file`, `--password-env`, stdin, and an interactive prompt for one known password. |
| ⬜ | **Find-all** **[batch]** | Honor `--find-all`: keep searching sibling/again instead of stopping at the first hit. |

## 2. Intermediate features

| | Feature | Notes |
|--|---------|-------|
| ⬜ | **Checkpoint / resume** **[batch]** | Persist search position for a long single-file run; resume after interruption. |
| ⬜ | **Full rule engine** **[batch]** | Complete hashcat rule-function set, rule stacking, reject rules, `.rule` files. |
| ⬜ | **Context / association candidates** **[batch]** | Seed candidates from filename, archive comments, document metadata, and strings harvested from already-decrypted siblings. |
| ⬜ | **Per-format fast-reject** **[batch]** | A cheap pre-check hook run before the expensive KDF to discard hopeless candidates. |
| ⬜ | **Candidate dedup** **[batch]** | A dedup wrapper (set / bloom filter) so masks×rules don't retry a string. |
| ⬜ | **Streaming large inputs** **[batch]** | Avoid materializing whole archives; stream bounded windows. |
| ⬜ | **Prometheus-format metrics** **[batch]** | Text exposition of `Pool.Metrics()` at `/metrics`. |
| ⬜ | **Combinator attack** **[batch]** | word₁+word₂ across two lists (+ optional separators/affixes). |
| ⬜ | **Hybrid attack** | wordlist ± mask (dict+mask / mask+dict). |
| ⬜ | `*2john` / hashcat hash-line emitters | Per-scheme `$…$` strings to complete the external-GPU bridge. |

## 3. Advanced features

| | Feature | Notes |
|--|---------|-------|
| ⬜ | **Observability** **[batch]** | Audit log of what was decrypted (no secrets); optional trace spans. |
| 🔬 | **Markov / PCFG generators** **[batch: Markov]** | Ordered statistical generation over a keyspace (Markov now; PCFG/OMEN later). |
| 🔬 | Distributed cracking | Keyspace sharding across a coordinator + workers. |
| 🔬 | GPU/OpenCL offload (external) | Out of tree; reached via the hash-line bridge above. |
| 🔬 | Adaptive scheduling | Order files/candidates by observed crackability; corpus-wide promotion. |
| 🔬 | Breach-corpus / spray sources | HIBP-style and org leak lists as first-class candidate sources. |

## 4. Cracking approaches

| | Approach | Notes |
|--|----------|-------|
| ✅ | Dictionary / wordlist | Implemented. |
| ✅ | Mask brute-force | Implemented (`?l?u?d?s?a?b` + `?1..?4`). |
| ✅ | Rule mangling (subset) | Implemented; full set is **[batch]** above. |
| ✅ | Password promotion | Implemented. |
| ✅ | Statistical **ordering** (Markov) | `candidates.ByScore` + `Markov`. |
| ⬜ | **Combinator** **[batch]** | See §2. |
| ⬜ | **Markov/PCFG generation** **[batch: Markov]** | See §3. |
| ⬜ | **Known-plaintext attack on ZipCrypto** **[batch]** | Biham–Kocher key recovery (bkcrack-style): recover the internal keys from ~12 known plaintext bytes, no password. ZipCrypto is cryptographically broken, so this is legitimate cryptanalysis (not weakening a sound cipher). |
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
