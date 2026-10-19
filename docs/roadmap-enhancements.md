# Xcrack — Enhancement Roadmap

A living, tracked backlog of features and attacks beyond the delivered format
set. The high-level phased plan lives in [`roadmap.md`](roadmap.md); this file
is the detailed, checkbox-level tracker.

**Status legend:** ✅ done · 🚧 in progress · ⬜ planned · 🔬 research / large

Items marked **[batch]** are the current implementation batch.

---

## Recently shipped (2026-10)

Two delivery cycles landed; all ✅ below are merged to `rom` and reflected in the
tables further down.

**Formats & attacks**
- ✅ **Crypto wallets — Ethereum keystore** (Web3 Secret Storage v3, `ethwallet`): scrypt / PBKDF2-HMAC-SHA256 → Keccak-256 MAC. See §5.
- ✅ **KeePass KDBX3.1** (AES-KDF + AES-256-CBC stream-start-bytes), alongside KDBX4. See §5.
- ✅ **Office 97/2000 40-bit RC4 key attack** ("Thunder Tables"): `xcrack office-keyattack FILE` sweeps the 2^40 trunc keyspace (shardable, parallel, resumable, allocation-free inner loop). See §4.
- ✅ **PDF 40-bit RC4 file-key attack** (V1/R2 and 40-bit R3/R4): `xcrack pdf-keyattack FILE` sweeps the 2^40 file-key space against the `/U` verifier — password-independent, shardable, parallel, R2 allocation-free hot loop. Cross-validated against a real qpdf-produced 40-bit PDF. See docs/CRACKING.md §3.
- ✅ **ZipCrypto cross-entry key reuse**: one recovery (known-plaintext or found password) unlocks the whole archive — `xcrack kp --decrypt … --zip ARCHIVE [--zip-out DIR]` seeds the shared entry-start state into every entry, each CRC-re-validated. See docs/CRACKING.md §3.
- ✅ **MS Access (Jet) header-XOR decode**: `xcrack access-recover FILE` reads a Jet3/Jet4 (.mdb) database password straight out of the header XOR obfuscation — no cracking. Cross-validated against jackcess (independent impl, known-password Jet4 fixture) and fuzzed; ACE (.accdb) has no shortcut and is declined. See docs/CRACKING.md §3.
- ✅ **VelvetSweatshop / empty-password** tried up front (read-only-recommended Excel, owner-only PDF) — zero-search recoveries. See docs/CRACKING.md.

**GPU tier (opt-in, server-only)**
- ✅ **PBKDF2-HMAC-SHA256 and -SHA512 kernels** (RAR5-class, SQLCipher-v4-class) beyond SHA-1; PRF-selectable `AccelKDF` seam.
- ✅ **Multi-device + batch autotune**; **vendor-aware autodetect** (NVIDIA / AMD / Intel / Apple / APU) with best-device selection and `XCRACK_GPU_DEVICE`.
- ✅ **More formats wired to the kernels**: ODF (PBKDF2-SHA-1 + `AccelKDF.PreHash` start-key hash) and RAR5 (PBKDF2-SHA-256 password-check fold). SQLCipher deliberately CPU-only (v3/v4 profile unknown pre-crack).
- ✅ **Office agile iterated-hash spin kernel** (SHA-1/256/384/512) — the ~100k-iteration loop that dominates every Office 2010+ document; a dedicated non-PBKDF2 kernel via the `accel.OfficeHasher` capability / `AccelKDF.Office` seam (CPU does the first hash, device does the spin, `Finish` runs the authoritative verifier). Office 2007 "standard" shares the kernel; only its `Finish` wiring remains.

**Candidate pipeline & orchestration**
- ✅ **Automatic cost-aware recovery queue** (`--cost-queue`): benchmark each file, attack weakest/fastest first.
- ✅ **Found-password cache** (`--found-cache` / `--remember`): reused passwords recovered instantly next run.
- ✅ **Loopback** (`--loopback`): re-mangle recovered passwords through the rules.
- ✅ **Full-run session resume** (`--session`); **potfile reporting** (`--show` / `--left`).
- ✅ **Candidate length filter** (`--min-length` / `--max-length`); **candidate encoding** (`--encoding` utf-8|latin1|utf-16le|utf-16be).
- ✅ **.hcmask mask files** (`--hcmask`); **Markov threshold** (`--markov-threshold`) and **position-aware (2D) Markov** (`--markov-pos`).
- ✅ **Rule-file debugging** (`--debug-rules`); fixed the `--pattern` DSL dropping the identity (`:`) rule.
- ✅ **Distributed resume / cross-run dedup** (`--cluster-session`).

New reference docs: **docs/CRACKING.md** (per-format attack + verification shortcuts), **docs/FAQ.md**.

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
| ✅ | **Find-all** | The tree is always fully explored by default (every encrypted node searched/reported independently). The explicit `--find-all` → `Options.FindAll` toggle (keep searching a node after its first successful match) is **reserved — not yet active**: the flag/`find_all` key parse but the engine ignores them today. |
| ✅ | **Time-limit (anti-stuck)** | `--time-limit D` (a clear alias of `--timeout`, per-file): a search that hits the budget is reported *locked* (exit 1), never an error, so one stuck file never fails a batch. |
| ✅ | **Language-specific wordlist** | `--swedish` ships an embedded ~31k Swedish-targeted list (`candidates.Swedish`, generated by `gen_swedish.go`): common Swedish words/names/places/clubs/holidays + typical mutations, ordered most-probable-first. |
| ✅ | **Candidate preview** (`--stdout`) | Print the assembled candidate stream (wordlists + rules + masks + generators) without cracking (hashcat `--stdout`); `--limit N` caps it. The way to debug rules/masks. |
| ✅ | **Keyspace size** (`--keyspace`) | Print the candidate keyspace: exact for masks/lists, counted for wordlists/rules (bounded by `--limit`). |
| ✅ | **Benchmark** (`--benchmark`/`-b`) | Measure the per-file verify rate (candidates/sec) by probing the file's real verifier — the per-format speed a recovery queue is ordered by. |
| ✅ | **Time estimate** (`--estimate`) | keyspace × measured rate → time-to-exhaust and expected-to-hit for each file; `--progress` also shows a true percent + candidate-rate ETA when the target keyspace is known. |
| ✅ | **Found-password cache** | `--found-cache FILE` / `--remember` (default `$XDG_DATA_HOME/xcrack/found.txt`): a persistent potfile whose passwords lead the candidate stream, so a reused password is recovered instantly on the next run. |
| ✅ | **Full-run session resume** | `--session FILE`: a multi-file batch records each file once fully searched (with any recovered passwords); re-running the same session skips finished files (batch-level complement to `--checkpoint`). |
| ✅ | **Potfile reporting** | `--show` / `--left` (hashcat): report which files the found-password cache already solves (`file:password`) or does not, without cracking. |
| ✅ | **Candidate length filter** | `--min-length` / `--max-length` (character bounds on the candidate stream). |
| ✅ | **Candidate encoding** | `--encoding utf-8\|latin1\|utf-16le\|utf-16be`: transcode each candidate before testing (legacy code-page or raw UTF-16 passwords). |

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
| ✅ | `*2john` / hashcat hash-line emitters | `xcrypto/hashline` + CLI `xcrack hashline`: emits `$office$` (-m 9400/9500/9600), `$pdf$` (-m 10400/10500/10600/10700), and `$zip2$` (WinZip AES, -m 13600). **Cross-validated against real hashcat** (`scripts/hashcat-xval.sh`: emitted lines are cracked back to the known password) and against hashcat's own example hashes. Challenge-derivable schemes plug into `Emit()`; schemes whose line needs bulk ciphertext the probe-time Challenge omits (e.g. `$zip2$`) implement `hashline.LineExporter` and re-read the file. Next emitters — `$7z$` (-m 11600), `$rar5$` (-m 13000), `$keepass$` (-m 13400) — are mostly deferred: the 7z format decodes through `bodgit/sevenzip`, which does not expose the salt/IV/coder fields its line requires; the KeePass line targets KDBX3 AES-KDF, whereas our support is KDBX4/Argon2d. **`$rar5$` is now unblocked:** `xcrypto/scheme/rar5` + the in-tree RAR5 header parser (`xfileformats/formats/archive/rar5crypt.go`) extract the salt, iteration-log and check value the decoder never exposed, so emitting the line is a small follow-up (the fast verifier that uses the same fields already ships). |
| ✅ | **.hcmask mask files** | `--hcmask FILE` (config `patterns.hcmask`): load hashcat `.hcmask` files — per-line masks with optional inline `?1..?4` custom charsets (`pattern.LoadHCMask`), escaped commas handled. |
| ✅ | **Markov threshold / position-aware** | `--markov-threshold N` caps the per-position branching of `--markov`; `--markov-pos` trains and generates from a position-aware (2D) Markov model (`candidates.MarkovPos`). |
| ✅ | **Rule-file debugging** | `--debug-rules` (hashcat `--debug-mode`): apply the `--pattern` rules to the wordlist and report per-rule kept/rejected counts with sample transforms. (Surfaced and fixed a `--pattern` DSL bug that dropped the identity `:` rule.) |
| ✅ | **Distributed resume / cross-run dedup** | `--cluster-session FILE`: persist the contiguous confirmed-tried offset per file and resume a distributed run without re-shipping covered candidates (`cluster.Options.ResumeOffsets`). |

## 3. Advanced features

| | Feature | Notes |
|--|---------|-------|
| ✅ | **Observability** | `Options.OnAudit` emits a secrets-free `AuditEvent` per node (path, format, status, encrypted, size) for an audit log or trace. |
| ✅ | **Markov / PCFG generators** | Markov generator (`candidates.MarkovGen`, best-first; CLI `--markov` / `--markov-max`) for statistical generation, plus a full Weir-style PCFG (`candidates.TrainPCFG` + `--pcfg`): learns a probabilistic grammar of structure/segments and enumerates guesses in probability order via the pre-terminal priority-queue (pivot-deduped). |
| ✅ | Distributed cracking (manual shard) | `candidates.Shard(src, index, count)` restricts a search to a disjoint 1/N stride of the keyspace; CLI `--shard I/N` (and the `search.shard` config key) wrap the whole candidate chain. Run `0/N`…`N-1/N` over the same inputs on separate machines — the shards partition the keyspace exactly (tested invariant) and each worker still tries promoted/context/hint guesses. Composes with the challenge export envelope (probe once, fan the heavy search out). A stride rather than contiguous blocks keeps a most-likely-first ordering spread across all shards. |
| ✅ | Distributed cracking (orchestrated cluster) | `pkg/cluster` + CLI `--server URL[@GROUP]` / `--cluster-mode collective\|partition` (and the `cluster` config block): xcrack coordinates a fleet of `xcrackd` workers over the HTTP API, streaming disjoint candidate batches. **Collective** = many servers on one file (first hit cancels the rest); **partition** = server groups on different files. The `xcrackd` API gained a multipart (`file`+`wordlist`) shape, server-side `shard=I/N`, and a `max-duration` hint. A worker only confirms a candidate it was handed, so it cannot cause a false positive. Tested against a real in-process fleet (collective + partition) and two real `xcrackd` processes. |
| ✅ | Challenge export/import CLI | `xcrack export-challenge FILE` emits the portable JSON challenge envelope(s); `xcrack --resume-from FILE` imports a recovered-password envelope and tries it first — surfacing the previously library-only `xcrypto.ExportChallenge`/`UnmarshalChallenge` on the command line. |
| 🔬 | GPU/OpenCL offload (external) | Out of tree; reached via the hash-line bridge above (`$office$`/`$pdf$`/`$zip2$`/`$dmg$`). |
| ✅ | GPU/OpenCL tier (in-tree, opt-in) | `xcrack/pkg/accel`: OpenCL batch KDF kernels for the **xcrackd server only**, behind `-tags opencl` (cgo + `-lOpenCL`). The default build stays pure-Go/cgo-free and CI never builds it (ADR 0001 amendment). **Kernels: PBKDF2-HMAC-SHA1, -SHA256 (RAR5-class) and -SHA512 (SQLCipher-v4-class)**, each byte-for-byte self-tested against the Go reference before use. The seam (`xfileformats.AccelKDF`) carries a PRF selector so the engine routes each target to the right kernel. **Multi-device**: a queue + kernel per device, batches split across devices concurrently, with a startup **batch-size autotune** (`accel.BatchTuner`). **Vendor-aware autodetect** (NVIDIA / AMD / Intel / Apple / Mesa / pocl, discrete-GPU > APU > CPU ranking, `XCRACK_GPU_DEVICE` override) — AMD GPUs and Ryzen APUs run through the OpenCL ICD; a native ROCm/HIP backend is a documented future (the kernels port directly). `xcrackd --gpu` is hardware-gated; validated end-to-end against WinZip-AES and real macOS DMG samples on the pocl device. More GPU-kernel candidates are catalogued in docs/CRACKING.md. |
| ✅ | Adaptive scheduling | Corpus-wide promotion (`Options.CorpusPromotion`, CLI `--adaptive`): a Pool-level learned-password set threads through each run's promoter, so a password recovered from any file is tried first on every other file and inner node, ordered by observed success (most repeatedly-effective first). The CLI also dispatches the smallest files first under `--adaptive`, so cheap wins seed the corpus before the big files run (results stay in argument order). Per-file promotion (inner layers) is unchanged when off. |
| ✅ | Breach-corpus / spray sources | `candidates.BreachCorpus`/`BreachFile` ingest frequency-annotated leak lists (SecLists `<count> <pw>` and HIBP-style `<pw>:<count>`, gzip auto-detected) most-common-first, with a `--breach-min-count` prevalence floor. `candidates.Spray`/`SprayCommon` build a compact spraying set — curated globally-common passwords plus org/product/user tokens mangled the way people pick (case, trailing year, `!`/`@`/`#` suffixes) and season+year / month+year walks. Wired as `--breach`/`--breach-min-count` and `--spray`/`--spray-token`/`--spray-year` (and the `candidates.breach*` / `search.spray*` config keys); spray is tried early, breach ahead of generic wordlists. Note: HIBP distributes *hashes*, not plaintext, so the online API stays out of scope (ADR); these sources consume local plaintext corpora only. |

## 4. Cracking approaches

| | Approach | Notes |
|--|----------|-------|
| ✅ | Dictionary / wordlist | Implemented. |
| ✅ | Mask brute-force | Implemented (`?l?u?d?s?a?b` + `?1..?4`). |
| ✅ | Rule mangling (full) | Broad hashcat function set + reject rules + stacking. |
| ✅ | Password promotion | Implemented. |
| ✅ | Statistical **ordering** (Markov) | `candidates.ByScore` + `Markov`; CLI `--order markov` reorders the wordlist candidates likeliest-first (distinct from `--markov` generation). |
| ✅ | **Combinator** | `candidates.Combinator`. |
| ✅ | **Markov/PCFG generation** | Markov ✅ (`MarkovGen`); PCFG ✅ (`candidates.TrainPCFG` + `--pcfg`) — Weir-style grammar, guesses emitted in probability order via the pre-terminal priority-queue enumeration (pivot-deduped). |
| ✅ | **Known-plaintext attack on ZipCrypto** | Full Biham–Kocher key recovery (bkcrack-style), implemented from the algorithm with this package's own verified primitives — no third-party code. `RecoverKeys(plain, cipher)` recovers the 96-bit internal state with **no password and no external reducer**: a keystream-only *Zreduction* of the key2 candidates (`reduceKey2`), full key2-window reconstruction (`exploreZ`), a fiber-accelerated key1 enumeration, and the verified key0 reconstruction + full re-encryption check. Correctness is proven end-to-end (`TestAutoPipelineRecovers`); the primitives are unit-tested as exact inverses. **Performance:** compute-heavy in pure Go — the keystream leaves ~10⁵ key2 candidates and the per-candidate key1 enumeration is ~2¹⁶. A two-step *fiber* roll-back (`msbProdFiber2`) pins the key0 low byte to ~2 candidates at **every** level, so the per-window cost is ~2¹⁶ `buildAndVerify` calls rather than ~2²⁴ (a ~34× per-window speedup, measured by `BenchmarkPerWindow`: 467 ms → 14 ms). The candidate search parallelizes near-linearly (measured ~16/28/62 cand·s⁻¹ on 1/2/4 cores); a representative full recovery examined ~185k candidates in **~57 min on a 4-core box** (down from an extrapolated ~30 h before the fiber speedup) — so minutes on a many-core server, an hour on a laptop, a small constant factor more from C++ bkcrack. `RecoverKeysBudget` bounds the effort; `RecoverKeysWith` + `ExternalBkcrack{Bin}` (CLI `--bkcrack`) offloads to a local bkcrack binary, and the key2 sequence can also be offloaded to an external engine via the challenge-export bridge. ZipCrypto is cryptographically broken, so this is legitimate cryptanalysis (not weakening a sound cipher). |
| ✅ | **Hybrid** (wordlist ± mask) | `pattern.Hybrid`; CLI `--hybrid-append` / `--hybrid-prepend`. |
| ✅ | PRINCE, toggle/keyboard-walk | `candidates.Prince` / `ToggleCase` / `KeyboardWalk`; CLI `--prince` / `--toggle-case` / `--keyboard-walk` (config `search.prince` / `toggle_case` / `keyboard_walk`). |
| ✅ | **Cost-aware recovery queue** | `--cost-queue` (config `search.cost_queue`): benchmark each input file's per-format verify rate and dispatch the fastest/weakest schemes first across a pile of files (the Elcomsoft recovery queue). |
| ✅ | **Loopback** | `--loopback` (hashcat `--loopback`): re-mangle the cached/pot recovered passwords through the rule set, tried early — catches a reused password with a new suffix/case. |
| ✅ | **Key-space attack (40-bit RC4)** | `xcrack office-keyattack` recovers the Office 97/2000 document key directly (see §5), and `xcrack pdf-keyattack` recovers a V1/R2 (or 40-bit R3/R4) PDF file key against the `/U` verifier — both bypass the password entirely. |
| ✅ | **MS Access Jet header-XOR decode** | `xcrack access-recover` reads a Jet (.mdb) database password straight out of the header XOR obfuscation — no cracking at all (cross-validated against jackcess). |
| ✅ | **ZipCrypto cross-entry reuse** | `xcrack kp --decrypt … --zip ARCHIVE` seeds one recovered entry-start state into every entry of the archive (shared password ⇒ shared pre-header key), decrypting them all with no further search (`--zip-out DIR`); each entry CRC-re-validated. |
| ✅ | **Position-aware Markov** | `--markov-pos` (2D Markov) and `--markov-threshold` (per-position branching cap), alongside `--markov` / `--order markov`. |

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
| ⬜ | BKS, JCEKS | Remaining Java key stores (JKS/PKCS#12 already ship). BKS = Bouncy Castle keystore (PBKDF + HMAC integrity); JCEKS = Sun's extended store (stronger PBE). Recover the store password via the integrity MAC, like JKS. |
| ⬜ | Disk images: ISO 9660/UDF, VHD(X), IMG | Dominant malware-delivery containers (unpack-and-recurse, not always crypto). **Parser + detection live in `xfileformats` (`formats/archive` or a new `formats/image`), never in the engine or CLI** — a new container is just a `Container`/`Encrypted` the recursion already drives. |
| ⬜ | MSI, CAB, SFX, NSIS/Inno installers | Common lures; unpack-and-recurse. **Parsers live in `xfileformats`** (MSI is an OLE2/CFB compound file — reuses `internal/cfb`; CAB/NSIS/Inno need new bounded parsers). |
| ✅ | **Microsoft Office family** (Access / Publisher / Visio / Project) | Encrypted **Publisher** (`.pub`), **Visio** (`.vsd`/`.vsdx`) and **Project** (`.mpp`) that use the standard Office encryption are **already decrypted by the shared `ooxml` path** — encrypted Office files of every application are the same CFB `EncryptionInfo`+`EncryptedPackage` (agile/standard) wrapper, so the engine recovers them content-first regardless of extension (regression-tested with a Visio-shaped package). **Access** (`.mdb` Jet, `.accdb` ACE) is a different, non-CFB container: the `access` format detects and names it (jet3/jet4/ace). **Jet (.mdb) password recovery is now implemented** — `xcrack access-recover` decodes it straight out of the header XOR obfuscation with no cracking, cross-validated against jackcess. Gaps: **ACE** (`.accdb`) recovery (an Office-style KDF with no shortcut — a password search, staged pending an oracle); legacy pre-2007 Publisher/Visio/Project binaries that use bespoke RC4-in-stream encryption (like `.doc/.xls/.ppt`) are not yet decoded (needs per-app stream layouts + an oracle). |
| ⬜ | OneNote `.one`, Outlook `.msg` / PST / MBOX | Mail/notes carriers. |
| ✅ | **SQLCipher** | Passphrase recovery via the page-1 HMAC (PBKDF2 → HMAC subkey → HMAC-SHA512/SHA1 over page 1), SQLCipher v4 and v3 profiles; cross-checked against the sqlcipher CLI. SQLCipher files have no cleartext magic, so they are not engine-autodetected; now reachable from the CLI via `xcrack --as sqlcipher FILE` (force-format), backed by the `xfileformats/formats/sqlcipher` wrapper over the scheme. |
| ✅ | **KeePass `.kdbx`** (KDBX4 **and KDBX3.1**) | KDBX4: passphrase recovery via the header HMAC-SHA256 (default **Argon2d** via the in-tree `xcrypto/prim/argon2`, cross-validated against the `argon2` CLI and x/crypto; Argon2id and legacy AES-KDF also handled). **KDBX3.1**: AES-KDF (TransformSeed/Rounds) + AES-256-CBC, verified by the header stream-start bytes. Cross-validated against pykeepass databases and (KDBX3) a fixture accepted by both KeePassXC 2.7.6 and pykeepass. Verify-only. |
| ✅ | **Crypto wallets — Ethereum keystore** | Web3 Secret Storage Definition v3 (`ethwallet`): the geth/MetaMask/MyEtherWallet keystore JSON, scrypt or PBKDF2-HMAC-SHA256 → 32-byte key, verified by the Keccak-256 MAC. Detected on the keystore JSON markers (never claims a non-wallet file); verify-only (the passphrase is the deliverable). Cross-validated against the two canonical Web3 test vectors (pbkdf2 MAC verbatim; scrypt MAC reproduced by a pycryptodome oracle and the Go path). |
| ✅ | **Legacy Office 40-bit RC4 key attack** | Office 97/2000 `.doc/.xls/.ppt` RC4 (`xcrypto/scheme/officebinary`): the password enters only as `trunc = MD5(UTF16LE(pw))[:5]` (40 bits), so `xcrack office-keyattack FILE` sweeps the 2^40 trunc keyspace against the verifier and recovers the document key regardless of password length ("Thunder Tables"). Shardable (`--shard i/N`), parallel, resumable, allocation-free inner loop. Office XP/2003 CryptoAPI RC4 is excluded (160-bit intermediate). Cross-validated against the msoffcrypto-tool KAT. Matches hashcat thread-3665 / mode 9710. |
| ✅ | **MS VBA project password** (MS-OVBA) | `xcrack vba-recover FILE` / `--as vbaproject` (`xcrypto/scheme/vbaproject`, `xfileformats/formats/vbaproject`): decodes the DPB field of the VBA `PROJECT` stream (MS-OVBA 2.4.3 reversible Data Encryption). A plaintext password is read with no cracking; a hashed one yields `SHA1(pw‖4-byte salt)` — a fast salted-SHA-1 crack (John `dynamic_24` / hashcat `-m 110 --hex-salt`). Works on legacy `.doc/.xls/.ppt`, standalone `vbaProject.bin`, and OOXML `.docm/.xlsm/.pptm`. Cross-validated against an independent MS-OVBA + hashlib reference (incl. NUL-byte key/hash cases); parsers fuzzed. The VBA source is never encrypted, so the password is the deliverable. |
| ✅ | **Apple iWork** (Pages/Numbers/Keynote) | Passphrase recovery for the modern '13+ format (.pages/.numbers/.key ZIP archives). The `.iwpv2` verifier is PBKDF2-HMAC-SHA1 → AES-128-CBC → `sha256(plain[:32])==plain[32:64]`; reverse-engineered from Pages/Numbers/Keynote 14.5 files and cross-validated against the known passphrase. Only the passphrase is recovered (document body not reconstructed). |
| ✅ | **ODF AES-256-GCM** | ODF 1.3's authenticated AES-256-GCM variant, alongside the existing AES-256-CBC (the GCM tag is the verifier; no false positives). Validated by round-trip (Go stdlib GCM) and the CBC path cross-validated against a real LibreOffice 24.2 document. |
| ⬜ | Hangul HWP/HWPX, WordPerfect, Lotus 1-2-3 | Remaining document suites. HWP is an OLE2/CFB compound file (reuses `internal/cfb`); HWPX is a ZIP (reuses the zip path); WordPerfect and Lotus 1-2-3 use bespoke legacy obfuscation needing per-format decode + an oracle. Parsers in `xfileformats`. |
| 🔬 | Full-volume: BitLocker, VeraCrypt/TrueCrypt, LUKS, FileVault2/APFS | Large, separate effort + threat review. The single biggest capability the commercial forensic suites (Passware, Elcomsoft) have and Xcrack lacks — volume parsing + the KDF per scheme; key-from-memory/recovery-key is the sibling item in the Gap review. Parsers in `xfileformats` (`formats/volume`). |
| ⬜ | Apple images: `.sparseimage` / `.sparsebundle`; iOS/iTunes backup keybag | `.sparseimage`/`.sparsebundle` extend the shipped DMG v1/v2 handling; the iOS/iTunes backup keybag (Manifest.plist + `Manifest.db`) is a passphrase-gated keybag. Parsers in `xfileformats`. |
| ✅ | **Codecs — zstd & lz4** | Single-stream compressors wired as containers (`xfileformats/formats/archive/codec.go`), so a file wrapped in a modern codec — most importantly `.tar.zst` / `.tar.lz4`, where the inner tar and any encrypted file in it were previously unreachable — is decompressed and recursed into. Pure-Go decoders already in the module (`klauspost/compress`, `pierrec/lz4`); bounded by `maxDecompressed` and the engine budgets. Round-trip + `.tar.zst` recursion tests. |
| ⬜ | More codecs: brotli, LZH, ARJ, ACE, SecureZIP | Archive breadth (zstd/lz4 shipped above). |
| ⬜ | More container parsers: cpio, ar, CAB, ISO 9660/UDF | New parsers (no pure-Go dep in tree yet); needed for installer/image carriers. |

## Gap review (2026-10) — candidates not yet tracked above

A sweep of the current feature set turned up these as the notable remaining gaps
(basic/intermediate UX is otherwise essentially complete):

**Search UX / interop (intermediate):**
- ✅ Rule *generation* (`--generate-rules N` / `--generate-rules-seed`, hashcat `-g`).
- ✅ Command-line mask custom charsets (`-1..-4` / `--custom-charset1..4`, hashcat `-1..-4`).
- ✅ Wordlist utilities (`xcrack wordlist`: `--dedupe`, `--sort`/`--sort-length`, `--min/max-length`, `--split N` — hashcat-utils `rli`/`splitlen` niche).
- ✅ Outfile-format control (`--outfile-format` 1=target/2=plain/3=hex-plain).
- ✅ Status heartbeat (`--status-timer N`).
- ✅ **Output result cache** (`--reuse-output`): skip re-extracting an unchanged source whose `-o` output is already present — the near-instant repeat run.
- ⬜ `.hcstat2` Markov stats import/export: deferred — the binary format has no in-container sample to validate against, and shipping an unverified parser would break the verify-first rule. Xcrack trains Markov/PCFG in-memory from the wordlist instead.
- ⬜ Association attack (hashcat `-a 9`): a specific hint bound 1:1 to a target — niche in a file-content model (the broad `--hint`/`--context` cover the common case); revisit on demand.

**Approaches / cryptanalysis (advanced):**
- ✅ **GPU kernels for the fast-hash attacks.** Office 97/2000 MD5+RC4
  (`office-keyattack --gpu`, `oldoffice_md5rc4` kernel) and PDF R2–R4 RC4
  (`pdf-keyattack --gpu`, `pdf_rc4keysearch` RC4-only kernel) — both 2^40
  key-search sweeps — plus the VBA project salted-SHA-1 batch (`vba_sha1` kernel,
  hashcat's `sha1($pass.$salt)` / mode 110), which offloads through the live crack
  loop on the OpenCL server tier (`xcrackd --gpu`), the same path WinZip-AES /
  DMG / ODF / RAR5 / Office-agile already use. All three reuse the shared
  MD5/RC4/SHA-1 cores and are validated against the CPU reference on pocl.
- 🚧 **Precomputed TMTO / "Thunder Tables" / rainbow tables** for the 2^40 RC4
  sweeps. **PDF V1/R2 shipped**: `xcrack thunder-gen` builds a rainbow table and
  `xcrack pdf-keyattack --table FILE` inverts `/U = RC4(fileKey, pad)` →
  40-bit file key in **sub-second**, no sweep. This is the ideal target because
  R2 `/U` is a salt- and ID-free function of the key, so **one table inverts every
  V1/R2 document** (`xcrypto/scheme/pdf/thundertable.go`: column-indexed rainbow
  chains, multi-sub-table coverage, compact binary store; every hit re-checked
  against the real `/U` and `VerifyFileKey`, so false alarms are rejected). The
  live sweep (`pdf-keyattack`, incl. `--gpu`) stays the no-precompute route and
  the miss fallback. ✅ **GPU-accelerated generation** shipped too:
  `thunder-gen --gpu` offloads the chain walk to an OpenCL device via the
  `pdf_thunderchain` kernel (one work-item per chain) and the `pdf.ChainComputer`
  seam — byte-identical to the CPU walk, so a GPU-built table is inverted by the
  same lookup (cross-validated GPU-vs-CPU byte-for-byte in the cmd tests), with a
  per-sub-table CPU fallback on any device error. ⬜ Remaining: **PDF R3/R4** (its
  `/U` hashes the per-file `/ID`) and **Office 97/2000** (per-file salt) are not
  cross-file-invertible, so a table there would be per-document — not worth it;
  they keep the sweep. ⬜ Multi-GPU split of generation (today the kernel runs on
  device 0) and shipping/hosting a prebuilt full 2^40 table.
- ✅ **Dual CPU+GPU parallel pipeline** (per-file race). On a host with both a CPU
  and a GPU, `--dual-pipeline` runs **two cracking lanes for the same file at
  once** — the GPU batch sweep on one side and the CPU search on the other — and
  the **first lane to find the password cancels the other for that file**, then
  both advance to the next file. This beats the default sequence (promoted/hint/
  context on CPU, *then* the GPU sweep) when the two streams are
  non-overlapping: a short high-yield wordlist clears on the CPU in the time the
  GPU spins up a large sweep, and neither side idles. Implemented with a per-file
  `context` cancellation token shared by both lanes, a mutex-guarded `sharedFeeder`
  so the lanes de-dup the one keyspace (each candidate tested on exactly one
  lane), and cost-aware batching (the GPU pulls large device batches, the CPU
  small ones for fast feedback). The authoritative CPU re-check gates every GPU
  hit, so a race cannot cause a false positive, and a mid-run device failure
  re-verifies the pending batch on the CPU before handing the rest to the CPU
  lane. `Options.DualPipeline` / `xcrack --gpu --dual-pipeline` /
  `xcrackd --gpu -dual-pipeline`; `pkg/xcrack/dualpipe.go`, stub-accelerator tests
  under `-race`. **Landed from user feedback (2026-10).**
- ⬜ **Broaden the GPU tier toward hashcat-level in-process throughput**: on-device
  rule mangling (rules evaluated on the GPU, not just host-generated candidates),
  more algorithms wired to the existing kernels (Office 2007 "standard" `Finish`,
  KeePass KDBX3 AES-KDF, SQLCipher-v4 PBKDF2-SHA512 once the v3/v4 profile is
  disambiguated), and a GPU path for the general per-candidate verifier rather
  than only the KDF. Today the GPU tier is server-only and covers a fixed kernel
  set (see §4 of CRACKING.md).
- 🔬 Neural candidate models (PassGAN / RNN), beyond the shipped Markov + PCFG.
- 🔬 Native CUDA / ROCm back-ends (OpenCL already runs on both via the ICD).
- (Staged cryptanalysis already catalogued in CRACKING.md §3: ZipCrypto Stay
  weak-RNG + reduced-known-plaintext, pure-Go ZipCrypto password-from-keys.)

**Formats (demand-driven):**
- 🔬 **Full-volume: BitLocker, VeraCrypt/TrueCrypt, LUKS, FileVault** (DFIR-critical; large, threat-review-gated).
- ⬜ **Crypto wallets beyond Ethereum**: Bitcoin `wallet.dat` (Berkeley DB), Electrum, Exodus, MetaMask vault.
- ⬜ **OS / browser credential stores**: Mozilla NSS (`key4.db` + `logins.json`), Windows DPAPI / Credential Manager, macOS Keychain, Chrome "Login Data".
- ⬜ **Password-manager vaults**: 1Password (`.opvault`/`.1pux`), Bitwarden/LastPass exports (KeePass already ships).
- ⬜ **Mail / notes carriers**: Outlook `.msg` / PST, MBOX, OneNote `.one` (malware delivery).
- ⬜ **Installers / disk images**: MSI, CAB, NSIS/Inno, SFX; ISO 9660/UDF, VHD(X), IMG (unpack-and-recurse).
- ⬜ **Java key stores**: BKS, JCEKS (JKS/PKCS#12 already ship).
- ⬜ **Regional / legacy docs**: Hangul HWP/HWPX; WordPerfect; Lotus 1-2-3.
- ⬜ **Apple**: `.sparseimage` / `.sparsebundle`, iOS/iTunes backup keybag (DMG v1/v2 already ship).
- ⬜ **More codecs / containers**: brotli, LZH, ARJ, ACE, SecureZIP; cpio, ar (zstd/lz4 already ship). Decoders/parsers in `xfileformats/formats/archive`; prefer pure-Go, bounded by the engine budgets.

### Competitor analysis (2026-10) — net-new capability gaps

A comparison against the field (raw crackers **hashcat** / **John the Ripper
Jumbo**; forensic suites **Passware Kit Forensic** / **Elcomsoft**; point tools
**bkcrack** / **Ophcrack**) surfaced these capabilities Xcrack lacks that are
**not** already a line item above. They are recorded here, not committed — Xcrack
stays a file-parsing recovery engine, so some are deliberately out of scope.

- ⬜ **Key-from-memory / recovery-key decryption** (Passware, Elcomsoft Forensic
  Disk Decryptor): recover a volume/file key from a RAM image, `hiberfil.sys` /
  pagefile, or an escrow/recovery key — often *instant* decryption with no
  search. Sibling to the full-volume item; parsing + key extraction in
  `xfileformats`.
- ⬜ **Forensic GUI, case management & reporting**: both commercial suites ship a
  GUI with evidence/case workflow, job queue and reports. Xcrack is CLI + the
  `xcrackd` HTTP service + Prometheus; a reporting/case layer (or a thin web UI
  over `xcrackd`) would close the operator-experience gap.
- ⬜ **Managed distributed: cloud-burst + agent fleet UI**: Passware spreads work
  across Windows/Linux/EC2/Azure via a Resource Manager; Hashtopolis/Fitcrack
  give hashcat a web UI with chunking and agent management. Xcrack has the
  `xcrackd` sharded cluster + `--cluster-session`; a web UI, auto-provisioning
  and cloud-burst would bring it to parity.
- ⬜ **hashcat "brain"-style shared reject**: a networked service that rejects
  already-tried candidates across the whole fleet (beyond the current
  `--cluster-session` cross-run dedup).
- ⬜ **Programmable candidate generators** (JtR "external" mode) and the deferred
  **`-a 9` association** / **`.hcstat2`** items (tracked above under Search UX).
- **Deliberately out of scope** (different domain, not a file-at-rest): mobile /
  cloud acquisition (iOS/Android backups, iCloud/Google, keychain); network-
  captured secrets (WPA/WPA2 handshakes, NetNTLM, Kerberoast); general OS/network
  hash types (NTLM/LM, etc.); FPGA/ASIC hardware. Xcrack bridges to hashcat/John
  for raw-hash work via `hashline` / `export-challenge`. See the FAQ's
  **Cracking limitations** and `CRACKING.md` for the rationale.

## Out of scope (non-goals)

In-tree GPU cracking · any online/network attack · weakening of **sound**
ciphers · document rendering / macro execution · public-key PDF (needs a
private key, not a password). See [`asr.md`](asr.md) §5.
