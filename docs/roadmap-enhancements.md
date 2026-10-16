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
| ✅ | **Mask length incrementing** | `pattern.ExpandIncrement(mask, min, max)` expands a mask over a token-length range, shortest-first; CLI `--increment MIN:MAX`. |
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
| ✅ | **Streaming large inputs** | The engine decomposes over a `source` backing that is either in-memory (small, the common case) or a temp-file-backed `ReaderAt` for large content. `spillSet.materializeReader` streams each opened entry and each freshly-decrypted payload to disk in 1 MiB windows above `Limits.SpillThreshold` (default 64 MiB), computing the SHA-256 incrementally — so a multi-GiB entry never occupies more than ~threshold+1 MiB of RAM, and format parsers (archive/zip, PDF, …) read it on demand via `io.SectionReader`. Verified end-to-end: a 100 MB AES-ZIP entry decrypts and writes back byte-for-byte while spilled to disk; the fuzz/bomb suite passes under `-race`. Remaining (staged): fully streaming *decompress* of deeply-nested containers without a spill file per layer, and streaming the authenticated schemes' plaintext before the whole-stream MAC verifies (currently each decrypted layer is finalized before the next). |
| ✅ | **Prometheus-format metrics** | `Metrics.WritePrometheus` + `GET /metrics` text exposition (alongside JSON `/v1/metrics`). |
| ✅ | **Combinator attack** | `candidates.Combinator(left, right, sep)`; CLI `--combinator-left FILE --combinator-right FILE [--combinator-sep S]` (hashcat `-a 1`). |
| ✅ | **Hybrid attack** | wordlist ± mask: `pattern.Hybrid` + CLI `--hybrid-append` / `--hybrid-prepend` (hashcat dict+mask / mask+dict); config `search.hybrid_append` / `search.hybrid_prepend`. |
| ✅ | `*2john` / hashcat hash-line emitters | `xcrypto/hashline` + CLI `xcrack hashline`: emits `$office$` (-m 9400/9500/9600), `$pdf$` (-m 10400/10500/10600/10700), and `$zip2$` (WinZip AES, -m 13600). **Cross-validated against real hashcat** (`scripts/hashcat-xval.sh`: emitted lines are cracked back to the known password) and against hashcat's own example hashes. Challenge-derivable schemes plug into `Emit()`; schemes whose line needs bulk ciphertext the probe-time Challenge omits (e.g. `$zip2$`) implement `hashline.LineExporter` and re-read the file. Next emitters — `$7z$` (-m 11600), `$rar5$` (-m 13000), `$keepass$` (-m 13400) — are deferred: the 7z/RAR formats decode through third-party libraries (`bodgit/sevenzip`, `nwaples/rardecode`) that do not expose the salt/IV/iteration-power/CRC/coder fields those lines require, so each needs format-layer plumbing (or a bespoke header re-parse) first; the KeePass line targets KDBX3 AES-KDF, whereas our support is KDBX4/Argon2d, which hashcat 13400 cracks only on some builds. |

## 3. Advanced features

| | Feature | Notes |
|--|---------|-------|
| ✅ | **Observability** | `Options.OnAudit` emits a secrets-free `AuditEvent` per node (path, format, status, encrypted, size) for an audit log or trace. |
| ✅ | **Markov / PCFG generators** | Markov generator (`candidates.MarkovGen`, best-first; CLI `--markov` / `--markov-max`) for statistical generation, plus a full Weir-style PCFG (`candidates.TrainPCFG` + `--pcfg`): learns a probabilistic grammar of structure/segments and enumerates guesses in probability order via the pre-terminal priority-queue (pivot-deduped). |
| ✅ | Distributed cracking | `candidates.Shard(src, index, count)` restricts a search to a disjoint 1/N stride of the keyspace; CLI `--shard I/N` (and the `search.shard` config key) wrap the whole candidate chain. Run `0/N`…`N-1/N` over the same inputs on separate machines — the shards partition the keyspace exactly (tested invariant) and each worker still tries promoted/context/hint guesses. Composes with the challenge export envelope (probe once, fan the heavy search out). A stride rather than contiguous blocks keeps a most-likely-first ordering spread across all shards. Still CPU-only and offline. A built-in coordinator that auto-assigns shards over the network is intentionally out of scope (orchestrate with any job runner). |
| 🔬 | GPU/OpenCL offload (external) | Out of tree; reached via the hash-line bridge above (`$office$`/`$pdf$`/`$zip2$`/`$dmg$`). |
| ✅ | GPU/OpenCL tier (in-tree, opt-in) | `xcrack/pkg/accel`: an OpenCL PBKDF2-HMAC-SHA1 batch kernel for the **xcrackd server only**, behind `-tags opencl` (cgo + `-lOpenCL`). The default build stays pure-Go/cgo-free and CI never builds it (ADR 0001 amendment). `xcrackd --gpu` is hardware-gated and `--gpu-selftest` proves the kernel is byte-for-byte identical to the Go reference before use (validated here against the pocl CPU device). The crack loop now routes acceleration-capable targets through the primitive: whole-file `xfileformats.Accelerable` formats (DMG) and container entries carrying an `Entry.Accel` (WinZip-AES) have their keyspace sweep batched onto the device via `Options.Accelerator`, re-checked by the CPU verifier, with transparent CPU fallback on any unsupported parameter. Validated end-to-end against WinZip-AES and real macOS DMG samples on the pocl device. |
| ✅ | Adaptive scheduling | Corpus-wide promotion (`Options.CorpusPromotion`, CLI `--adaptive`): a Pool-level learned-password set threads through each run's promoter, so a password recovered from any file is tried first on every other file and inner node, ordered by observed success (most repeatedly-effective first). The CLI also dispatches the smallest files first under `--adaptive`, so cheap wins seed the corpus before the big files run (results stay in argument order). Per-file promotion (inner layers) is unchanged when off. |
| ✅ | Breach-corpus / spray sources | `candidates.BreachCorpus`/`BreachFile` ingest frequency-annotated leak lists (SecLists `<count> <pw>` and HIBP-style `<pw>:<count>`, gzip auto-detected) most-common-first, with a `--breach-min-count` prevalence floor. `candidates.Spray`/`SprayCommon` build a compact spraying set — curated globally-common passwords plus org/product/user tokens mangled the way people pick (case, trailing year, `!`/`@`/`#` suffixes) and season+year / month+year walks. Wired as `--breach`/`--breach-min-count` and `--spray`/`--spray-token`/`--spray-year` (and the `candidates.breach*` / `search.spray*` config keys); spray is tried early, breach ahead of generic wordlists. Note: HIBP distributes *hashes*, not plaintext, so the online API stays out of scope (ADR); these sources consume local plaintext corpora only. |

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
| ✅ | **Known-plaintext attack on ZipCrypto** | Full Biham–Kocher key recovery (bkcrack-style), implemented from the algorithm with this package's own verified primitives — no third-party code. `RecoverKeys(plain, cipher)` recovers the 96-bit internal state with **no password and no external reducer**: a keystream-only *Zreduction* of the key2 candidates (`reduceKey2`), full key2-window reconstruction (`exploreZ`), a fiber-accelerated key1 enumeration, and the verified key0 reconstruction + full re-encryption check. Correctness is proven end-to-end (`TestAutoPipelineRecovers`); the primitives are unit-tested as exact inverses. **Performance:** compute-heavy in pure Go — the keystream leaves ~10⁵ key2 candidates and the per-candidate key1 enumeration is ~2¹⁶. A two-step *fiber* roll-back (`msbProdFiber2`) pins the key0 low byte to ~2 candidates at **every** level, so the per-window cost is ~2¹⁶ `buildAndVerify` calls rather than ~2²⁴ (a ~34× per-window speedup, measured by `BenchmarkPerWindow`: 467 ms → 14 ms). The candidate search parallelizes near-linearly (measured ~16/28/62 cand·s⁻¹ on 1/2/4 cores); a representative full recovery examined ~185k candidates in **~57 min on a 4-core box** (down from an extrapolated ~30 h before the fiber speedup) — so minutes on a many-core server, an hour on a laptop, a small constant factor more from C++ bkcrack. `RecoverKeysBudget` bounds the effort; `RecoverKeysWith` + `ExternalBkcrack{Bin}` (CLI `--bkcrack`) offloads to a local bkcrack binary, and the key2 sequence can also be offloaded to an external engine via the challenge-export bridge. ZipCrypto is cryptographically broken, so this is legitimate cryptanalysis (not weakening a sound cipher). |
| ✅ | **Hybrid** (wordlist ± mask) | `pattern.Hybrid`; CLI `--hybrid-append` / `--hybrid-prepend`. |
| ✅ | PRINCE, toggle/keyboard-walk | `candidates.Prince` / `ToggleCase` / `KeyboardWalk`; CLI `--prince` / `--toggle-case` / `--keyboard-walk` (config `search.prince` / `toggle_case` / `keyboard_walk`). |

## 5. Application file formats

Implemented: ZIP (ZipCrypto/WinZip-AES), tar/gzip/bzip2/xz, 7z & RAR (incl.
header-encrypted), OOXML, legacy MS Office (.doc/.xls/.ppt), **Office family via
the shared OOXML path (Publisher/Visio/Project when agile/standard-encrypted)**,
PDF, ODF, MIME (.eml), age, symmetric OpenPGP, OpenSSH private keys, encrypted
PEM/PKCS#8 keys, JKS, PKCS#12, PuTTY .ppk, SQLCipher (via `--as sqlcipher`),
Apple iWork (Pages/Numbers/Keynote), KeePass KDBX4 (.kdbx), Apple encrypted DMG
(v1/v2, via dmg2john `$dmg$`), MS Access detection (.mdb/.accdb).

| | Format(s) | Notes |
|--|-----------|-------|
| ✅ | **OpenSSH private keys** | bcrypt-pbkdf + aes-ctr; verified via x/crypto/ssh, cross-checked against ssh-keygen. |
| ✅ | **Encrypted PEM / PKCS#8 keys** | Traditional DEK-Info (EVP_BytesToKey) and PBES2 (PBKDF2 / scrypt + AES-CBC); cross-checked against OpenSSL. |
| ✅ | **JKS (Java KeyStore)** | Store-password recovery via the trailing SHA-1 integrity digest; cross-checked against keytool. |
| ✅ | **PKCS#12 (.p12/.pfx)** | Password recovery via the PFX MacData MAC (PKCS#12 KDF, RFC 7292 B.2 + HMAC); algorithm-independent of the bag encryption, cross-checked against OpenSSL (modern SHA-256/AES and legacy SHA-1/3DES). |
| ✅ | **PuTTY `.ppk`** | v3 (Argon2id/i) and v2 (legacy SHA-1); passphrase verified by the Private-MAC after decrypting the private section; cross-checked against puttygen. |
| ⬜ | BKS | Remaining Java key store. |
| ⬜ | Disk images: ISO/UDF, VHD(X), IMG | Dominant malware-delivery containers (unpack, not always crypto). |
| ⬜ | MSI, CAB, SFX, NSIS/Inno installers | Common lures; unpack. |
| ✅ | **Microsoft Office family** (Access / Publisher / Visio / Project) | Encrypted **Publisher** (`.pub`), **Visio** (`.vsd`/`.vsdx`) and **Project** (`.mpp`) that use the standard Office encryption are **already decrypted by the shared `ooxml` path** — encrypted Office files of every application are the same CFB `EncryptionInfo`+`EncryptedPackage` (agile/standard) wrapper, so the engine recovers them content-first regardless of extension (regression-tested with a Visio-shaped package). **Access** (`.mdb` Jet, `.accdb` ACE) is a different, non-CFB container: the `access` format detects and names it (jet3/jet4/ace). Gaps: Access password *recovery* is staged (no validated oracle in this build); legacy pre-2007 Publisher/Visio/Project binaries that use bespoke RC4-in-stream encryption (like `.doc/.xls/.ppt`) are not yet decoded (needs per-app stream layouts + an oracle). |
| ⬜ | OneNote `.one`, Outlook `.msg` / PST / MBOX | Mail/notes carriers. |
| ✅ | **SQLCipher** | Passphrase recovery via the page-1 HMAC (PBKDF2 → HMAC subkey → HMAC-SHA512/SHA1 over page 1), SQLCipher v4 and v3 profiles; cross-checked against the sqlcipher CLI. SQLCipher files have no cleartext magic, so they are not engine-autodetected; now reachable from the CLI via `xcrack --as sqlcipher FILE` (force-format), backed by the `xfileformats/formats/sqlcipher` wrapper over the scheme. |
| ✅ | **KeePass `.kdbx`** (KDBX4) | Passphrase recovery via the header HMAC-SHA256. KDBX4's default KDF is **Argon2d**, which `golang.org/x/crypto` does not expose (only Argon2i/id), so Xcrack ships an in-tree Argon2 (`xcrypto/prim/argon2`, all three variants) cross-validated against the reference `argon2` CLI (d) and x/crypto (i/id). Argon2id and the legacy AES-KDF are also handled. Cross-validated against pykeepass-produced databases. Verify-only (the DB body is not reconstructed). |
| ✅ | **Apple iWork** (Pages/Numbers/Keynote) | Passphrase recovery for the modern '13+ format (.pages/.numbers/.key ZIP archives). The `.iwpv2` verifier is PBKDF2-HMAC-SHA1 → AES-128-CBC → `sha256(plain[:32])==plain[32:64]`; reverse-engineered from Pages/Numbers/Keynote 14.5 files and cross-validated against the known passphrase. Only the passphrase is recovered (document body not reconstructed). |
| ✅ | **ODF AES-256-GCM** | ODF 1.3's authenticated AES-256-GCM variant, alongside the existing AES-256-CBC (the GCM tag is the verifier; no false positives). Validated by round-trip (Go stdlib GCM) and the CBC path cross-validated against a real LibreOffice 24.2 document. |
| ⬜ | Hangul HWP | Remaining document suite. |
| 🔬 | Full-volume: BitLocker, VeraCrypt, LUKS, FileVault | Large, separate effort + threat review. |
| ⬜ | More codecs: zstd, lz4, brotli, LZH, ARJ, ACE, SecureZIP | Archive breadth. |

## Out of scope (non-goals)

In-tree GPU cracking · any online/network attack · weakening of **sound**
ciphers · document rendering / macro execution · public-key PDF (needs a
private key, not a password). See [`asr.md`](asr.md) §5.
