# Changelog

All notable changes to Xcrack. The format follows
[Keep a Changelog](https://keepachangelog.com/); the project has not yet cut
tagged releases, so entries are grouped by the pull request that landed them
(newest first) with the merge date. Dates are UTC.

Scope note: Xcrack is a defensive / recovery tool. Every cryptographic scheme is
cross-validated against an external oracle (known-answer vectors or a real CLI),
hostile-input parsers are fuzzed, and the default build stays pure-Go and
CPU-only (the GPU tier is an opt-in, hardware-gated server exception).

## [Unreleased]

Work on branch `claude/loving-wozniak-mmti5f`, not yet merged.

### Added
- **GPU kernel: PDF 40-bit RC4 file-key search.** The second key-SEARCH OpenCL
  kernel: `pdf-keyattack --gpu` offloads the PDF Standard Security Handler's 2^40
  file-key sweep (V1/R2 and 40-bit R3/R4) to an OpenCL device. Because the file
  key is `MD5(…)[:5]` and `/U` is a function of that 5-byte key alone,
  `kernel_pdf_rc4keysearch.cl` is **RC4-only** — the one per-document MD5 the R3/R4
  path needs (`MD5(pad‖ID)`) is constant across keys and precomputed on the host
  (`pdf.Handler.RC4KeyAttackParams`), so each work-item just RC4s the input
  `rounds` times (round `r` keyed by `key5 XOR r`) and compares to `/U`. It reuses
  the MD5+RC4 cores and the hit/atomic plumbing of the Office sweep. The new
  `accel.PDFRC4KeySearcher` capability drives it, with transparent CPU fallback
  (`pdf.Handler.RC4KeyAttack`) and an authoritative CPU re-check of any hit
  (`pdf.Handler.VerifyFileKey`). Validated on pocl against the CPU reference —
  `GPUSelfTest` gains R2 and R3/R4 cases, plus a kernel cross-validation test and a
  `-tags opencl` end-to-end CLI test. Default build stays pure-Go (ADR 0001); ships
  only with `-tags opencl`.
- **GPU kernel: Office 97/2000 40-bit MD5+RC4 key search.** The first key-SEARCH
  OpenCL kernel (distinct from the per-password PBKDF2/Office-spin batch kernels):
  `office-keyattack --gpu` offloads the 2^40 trunc sweep (the Elcomsoft "Thunder
  Tables" / hashcat thread-3665 attack) to an OpenCL device. `kernel_oldoffice_
  md5rc4.cl` does MD5 + RC4 per trunc index on the device; the new
  `accel.OldOfficeKeySearcher` capability drives it, with transparent CPU fallback
  and an authoritative CPU re-check (`officebinary.VerifyRC4Trunc`) of any hit.
  Validated on pocl against the CPU reference (`officebinary.RC4KeyAttack`) —
  `GPUSelfTest` gains an oldoffice case, plus a kernel cross-validation test and a
  `-tags opencl` end-to-end CLI test. Default build stays pure-Go (ADR 0001);
  ships only with `-tags opencl`. PDF R2–R4 (same key-search shape) shipped as the
  follow-up above.
- **CLI parity features (basic/intermediate gap review).**
  - `-1/-2/-3/-4` (`--custom-charset1..4`): command-line mask custom charsets
    `?1..?4` (hashcat `-1..-4`), used by `--hcmask`/`--pattern` masks.
  - `--generate-rules N` (`--generate-rules-seed S`): fold N reproducible random
    mangling rules into the rule pool (hashcat `-g`); `pattern.GenerateRules`
    emits only rules that compile.
  - `xcrack wordlist`: wordlist maintenance (hashcat-utils niche) — `--dedupe`,
    `--sort`/`--sort-length`, `--min-length`/`--max-length`, `--split N`.
  - `--outfile-format LIST`: found-password line format for `--results-file`/
    stdout (1=target, 2=plain, 3=hex-plain).
  - `--status-timer N`: a files-done/elapsed heartbeat every N seconds.
- **`--reuse-output` output result cache.** With `-o`, record each source's
  content hash + candidate signature + recovered passwords in a per-output
  `.xcrack-stamp`, and on a repeat run skip any still-valid source entirely — no
  verification KDF, no decrypt, no decompose, no rewrite. This is the gap behind
  "why isn't a cached re-run instant?": `--found-cache` only *orders* candidates
  (so the known password is tried first, skipping wrong-guess KDFs) but still
  re-verifies and re-extracts every run; `--reuse-output` skips the file. A warm
  `--reuse-output -o DIR samples/*` run drops from ~18s to ~0.02s.
- **MS VBA project password recovery (MS-OVBA).** `xcrack vba-recover FILE` and
  `--as vbaproject` recover the VBA IDE "lock project for viewing" password from
  the DPB field of the VBA `PROJECT` stream (MS-OVBA 2.4.3 reversible Data
  Encryption). A plaintext password is read out with no cracking; a hashed one is
  `SHA1(password‖4-byte salt)` — a fast salted-SHA-1 verifier crackable in-engine
  (`--as vbaproject`) or via the emitted John `dynamic_24` / hashcat `-m 110
  --hex-salt` lines. Works on legacy `.doc/.xls/.ppt`, a standalone
  `vbaProject.bin`, and OOXML `.docm/.xlsm/.pptm` (the `word/vbaProject.bin` part
  is unwrapped). New `xcrypto/scheme/vbaproject` (transform round-trip tested,
  salted-SHA-1 cross-validated against an independent MS-OVBA + hashlib reference
  over golden fixtures incl. NUL-byte key/hash cases) and
  `xfileformats/formats/vbaproject` (force-only; parsers fuzzed). The VBA source
  is never encrypted, so only the password is the deliverable.
- **Codecs: zstd & lz4 containers.** Two single-stream compressors are registered
  as containers (`xfileformats/formats/archive/codec.go`), so a password-protected
  file wrapped in a modern codec — most importantly `.tar.zst` / `.tar.lz4`, where
  the inner tar and any encrypted file in it were previously unreachable — is
  decompressed and recursed into like gzip/bzip2/xz. Pure-Go decoders already in
  the module (`klauspost/compress/zstd`, `pierrec/lz4/v4`, now promoted to direct
  requires), so the cgo-free default build is unaffected; output is bounded by
  `maxDecompressed` and the engine budgets, and decode errors surface as
  recovered-so-far / `ErrMalformed`, never a panic. zstd detection also covers
  skippable frames. Tested by round-trip + a `.tar.zst` recursion test and an
  end-to-end engine test that cracks a WinZip-AES entry inside a `.tar.zst`.
- **GPU kernel: Office 2010+ agile iterated-hash spin.** A new OpenCL kernel
  (SHA-1/256/384/512) runs the ~100k-iteration spin that dominates every modern
  Office document's key derivation — the single biggest per-candidate cost for
  encrypted OOXML. It is not a PBKDF2: the CPU does the one variable-length first
  hash `H(salt‖UTF16LE(pw))` and the device runs the fixed-size loop
  `cur = H(LE32(i)‖cur)` (a new optional `accel.OfficeHasher` capability and
  `AccelKDF.Office` seam; ooxml exposes it via `AccelKDF`, with `Finish` running
  the authoritative agile verifier on the device-derived digest). Byte-for-byte
  self-tested against `prim.OfficeAgileHash` for all four hashes at startup and
  validated end-to-end through the engine against pocl (`TestOpenCLOfficeAgileLive`)
  and with a pure-Go stub in the default build (`TestAccelOfficeAgile`). The spin
  kernel is shared with Office 2007 "standard"; only that scheme's post-spin
  `Finish` wiring remains.
- **GPU acceleration for ODF and RAR5.** The opt-in OpenCL tier already shipped
  PBKDF2-HMAC-SHA1/256/512 kernels but only WinZip-AES and encrypted DMG were
  wired to them. Now **ODF** offloads its PBKDF2-HMAC-SHA1 content-key spin (via
  a new `AccelKDF.PreHash` field that applies ODF's SHA-256/SHA-1 start-key hash
  to each candidate on the CPU before the kernel), and **RAR5** offloads its
  PBKDF2-HMAC-SHA256 password-check derivation (the 8-byte check value is a fold
  of `PBKDF2-HMAC-SHA256(pw, salt, 2^Lg2Count+32, 32)`). Both validated against
  pocl end-to-end through the engine, with the CPU verifier re-checking every
  hit. SQLCipher is deliberately left on the CPU (its v3/v4 profile is unknown
  before a password verifies, and the seam derives one profile per candidate).
  New scheme helpers: `odf.VerifyWithKey`/`DecryptCompressedWithKey`/
  `AccelStartHash`, `rar5.PswCheckFromDK`/`VerifyDK`/`AccelIterations`.
- **`--show-config`** — print the effective configuration (flags + env + config
  file + defaults, merged, with precedence noted) and exit without cracking. It
  shows counts for explicit passwords and the cache path, never secret values,
  so it is safe to paste into a bug report.
- **`--show-cache`** — list the passwords held in the found-password cache /
  potfile and exit (needs `--found-cache`/`--remember`/`--potfile`). Distinct
  from `--show`, which reports which *files* the cache solves.
- **`--extract-suffix S`** (config `output.extract_suffix`) — change the
  per-source extracted-tree directory suffix under `--out` (default
  `.extracted`; `''` = the bare source name). Validated as a single path segment
  (no `/` or `..`) so it can never redirect the write outside `--out`.

### Tests
- **`gold/` cross-validation fixture index.** A top-level `gold/README.md` records
  the provenance (source tool/version or spec, licence, known answer, in-repo
  path) of every externally-sourced cross-validation fixture, so cross-validation
  survives the source moving/disappearing; fixtures stay committed in-tree with a
  per-directory `ATTRIBUTION.md`. Committed `gold/vba/vba_oracle.py` (the MS-OVBA
  reference generator for the VBA DPB fixtures, previously output-only; verified
  to reproduce them). Filled two missing `ATTRIBUTION.md` files (the qpdf PDFs and
  the header-encrypted `hdr.7z`/`hdr.rar`).

### Docs
- **Mermaid attack-pipeline diagram** added to README.md ("How it works") and
  docs/CRACKING.md §1 (replacing the ASCII sketch): detect → probe → candidate
  stream → fast-reject → verify → decrypt → re-detect, with the opt-in GPU tier
  and the verification-shortcut branch shown. (Diamond labels shortened so GitHub's
  renderer no longer clips them.)
- FAQ: explain why a cached re-run isn't instant (candidate-ordering vs result
  cache) and point to `--reuse-output`; USAGE documents the new flags.
- CRACKING.md §3 + REFERENCES.md: record hashcat forum **thread-3665**
  ("Colliding password protected MS office 97-2003 documents") as the canonical
  reference for the Office 97/2000 40-bit MD5+RC4 key attack Xcrack already ships
  as `office-keyattack` — its collider `-m 9710` opens the document without the
  real password, `-m 9720` finds the password, and SHA1+RC4 CryptoAPI is the
  separate `-m 9800` (correctly out of scope). VBA documented across CRACKING.md
  (§2 table + §3), FILEFORMATS.md, FAQ.md, TERMINOLOGY.md (VBA/DPB/MBCS) and
  roadmap-enhancements.md; MS-OVBA + Didier Stevens added to REFERENCES.md §8.
- README: add the `docs/CRACKING.md` and `docs/FAQ.md` references to the
  documentation index; correct the MS Access rows now that Jet `.mdb` recovery
  ships (ACE `.accdb` recovery remains staged).
- USAGE: a new **Use cases** section mapping nine end-to-end scenarios
  (malware triage, DFIR batch, forgotten password, pentest, no-crack recoveries,
  GPU offload, distributed, service, inspect-first) to commands; document
  `--extract-suffix`, `--show-config`, `--show-cache`.
- FAQ: new **Output & extracted files** and **Inspecting & troubleshooting**
  categories, plus entries for the new flags, formats, logging and exit codes.
- FAQ: new **GPU acceleration** category — what the device does vs. the CPU, the
  accelerated-formats table, why a scheme stays on the CPU (memory-hard /
  ambiguous profile / no kernel yet), multi-device selection, and the
  no-false-positive guarantee.
- CRACKING.md §3: record a fresh cryptanalysis survey of every supported format.
  Net outcome — the formats are already well covered; the notable additions are
  (a) a precise refutation of the common claim that Office **XP/2003 CryptoAPI**
  40-bit RC4 is key-attackable (each block key derives from the 160-bit
  `SHA1(salt‖pw)`, so recovering the 40-bit verifier key decrypts only block 0,
  not the document), (b) making explicit that the empty-**user**-password key
  derivation already decrypts owner-only PDFs of *every* revision (128-bit RC4
  and AES included — the only feasible route there), and (c) documenting the Wu
  2005 RC4 keystream-reuse weakness and the pure-Go ZipCrypto password recovery
  as known-but-not-built, with reasons.
- CRACKING.md §3 + REFERENCES.md: from two further Elcomsoft posts (legacy-ZIP
  known-plaintext; the history of PDF insecurity) — document the **Stay 2001**
  ZipCrypto results (reduced 2–3-byte known-plaintext, and the weak-RNG
  "guaranteed recovery" against WinZip ≤ 8.0 / NetZip with ≥ 5 entries) as staged,
  with reasons (recovered keys already suffice; no obtainable oracle for the
  weak-RNG tail); and record that PDF **R5** (Acrobat 9 AESV3) verifies with a
  **single SHA-256**, cheaper per guess than the iterated R6 — a property Xcrack's
  R5 verifier already has (`hash2B` short-circuits for `R < 6`).
- Roadmap: mark **Document explosion** (`--explode-documents`, ADR 0007) done, and
  add zstd/lz4 to the archive-unpackers entry; `roadmap-enhancements.md` marks the
  zstd/lz4 codecs shipped and splits out the remaining codecs / container parsers
  (brotli, cpio, ar, CAB, ISO 9660/UDF).
- Terminology moved out of `docs/README.md` into a new, extensively expanded
  **docs/TERMINOLOGY.md** (engine concepts, KDFs & hashing, ciphers & modes,
  formats & key stores, attacks & cryptanalysis shortcuts, acceleration, and an
  abbreviations/TLA index), referenced from README.md and docs/README.md.

## PR #19 — 2026-10-17 — Staged cryptanalysis shortcuts: ZipCrypto cross-entry, PDF 40-bit RC4, Access Jet

### Added
- **ZipCrypto cross-entry key reuse** — every entry in a ZipCrypto archive
  shares one password-derived pre-header key state, so a single recovery unlocks
  the whole archive. `xcrack kp --decrypt … --zip ARCHIVE [--zip-out DIR]` seeds
  the recovered entry-start state (`zip.DecryptArchiveWithStart`) into every
  other entry and decrypts them all with no further search; each entry is
  independently CRC-re-validated and AES / non-ZipCrypto entries are skipped.
- **PDF 40-bit RC4 file-key attack** — `xcrack pdf-keyattack FILE`
  (`xcrypto/scheme/pdf.Handler.RC4KeyAttack`): the PDF file key is a single MD5
  truncated to 5 bytes, independent of the password's length, so the 2^40
  file-key space is swept directly against the `/U` verifier and recovered with
  no password, from the public `/U`, `/ID` and revision alone. Covers V1/R2 and
  40-bit R3/R4; the common R2 case runs an allocation-free inline-RC4 hot loop.
  Shardable (`--shard i/N`), parallel (`--workers`); 128-bit RC4 and the AES
  schemes are declined. Cross-validated against a real 40-bit PDF produced by
  qpdf (`keyattack_test.go`).
- **MS Access (Jet) header-XOR decode** — `xcrack access-recover FILE`
  (`xfileformats/formats/access.RecoverJetPassword`): Jet3/Jet4 (.mdb) store the
  database password XOR-obfuscated with fixed, public material (a 128-byte header
  mask, plus a creation-date-derived 4-byte mask on Jet4), so the password is
  read straight out of the header with no cracking. ACE (.accdb, Access 2007+)
  uses a real Office-style KDF and is declined. Cross-validated against jackcess
  (an independent implementation that produced a known-password Jet4 fixture)
  and fuzzed against hostile headers. This clears the last of the three
  cryptanalysis shortcuts that CRACKING.md §3 had staged.

### Fixed
- `resolveRange` (the `--shard`/`--start`/`--max` keyspace splitter) now takes
  the keyspace size explicitly, shared cleanly between the Office trunc sweep and
  the new PDF file-key sweep (both 2^40).

## PR #18 — 2026-10-17 — Found-password cache, session/potfile, basic+intermediate features, GPU vendors, CRACKING.md

### Added
- **Found-password cache** — `--found-cache FILE` / `--remember` (default
  `$XDG_DATA_HOME/xcrack/found.txt`): a persistent potfile whose passwords lead
  the candidate stream, so a reused password is recovered instantly on the next
  run. Priority passwords now lead the per-file stream, ahead of the generators.
- **Full-run session resume** (`--session FILE`): a multi-file batch records each
  file once fully searched (with any recovered passwords) and skips finished
  files on re-run — the batch-level complement to `--checkpoint`.
- **Potfile reporting** (`--show` / `--left`, hashcat): report which files the
  found-password cache already solves, without cracking.
- **Loopback** (`--loopback`): re-mangle the cached/pot recovered passwords
  through the rules, tried early.
- **Candidate length filter** (`--min-length` / `--max-length`) and **encoding**
  (`--encoding utf-8|latin1|utf-16le|utf-16be`).
- **.hcmask mask files** (`--hcmask`, config `patterns.hcmask`): per-line masks
  with inline `?1..?4` charsets.
- **Markov threshold / position-aware** — `--markov-threshold N` caps the
  per-position branching; `--markov-pos` trains and generates from a 2D
  (position-aware) Markov model.
- **Rule-file debugging** (`--debug-rules`): per-rule kept/rejected counts and
  sample transforms. Also fixed a `--pattern` DSL bug that silently dropped the
  identity (`:`) rule.
- **VelvetSweatshop / empty password** tried up front (read-only-recommended
  Excel, owner-only PDF) — zero-search recoveries.
- **Distributed resume / cross-run dedup** (`--cluster-session FILE`): resume a
  fleet run without re-shipping candidates already confirmed tried
  (`cluster.Options.ResumeOffsets`, a safe contiguous-completed offset).
- **GPU vendor-aware autodetect**: the OpenCL tier ranks and selects the best
  device across NVIDIA / AMD / Intel / Apple / APU (`accel.VendorArch`,
  `DeviceRank`, `XCRACK_GPU_DEVICE`); AMD GPUs and Ryzen APUs run through the
  OpenCL ICD. xcrackd logs the vendor family per device.
- New reference docs: **docs/CRACKING.md** (per-format attacks, verification
  shortcuts & cryptanalysis, GPU-kernel candidates) and **docs/FAQ.md**; a
  complete config-key reference in **config/README.md**.

### Performance
- The Office 97/2000 2^40 RC4 key-attack inner loop is now allocation-free
  (reused mixing buffer, stack RC4 state, value-array MD5): per-candidate heap
  allocations drop from ~4 to zero, removing the GC pressure that dominated a
  sustained sweep.

## PR #16–#17 — 2026-10-17 — Inspection modes, crypto wallets, KDBX3, Office 40-bit key attack, GPU SHA-256/512, multi-GPU, cost queue

### Added
- **Ethereum keystore wallets** (Web3 Secret Storage v3, the `ethwallet`
  format): scrypt / PBKDF2-HMAC-SHA256 key derivation verified by the
  Keccak-256 MAC, detected on the keystore JSON markers. Cross-validated against
  the two canonical geth test vectors (the pbkdf2 MAC is the verbatim published
  value; the scrypt MAC is reproduced identically by a pycryptodome oracle and
  the Go path).
- **Legacy KeePass KDBX3.1** passphrase recovery in the `keepass` scheme/format
  (AES-KDF + AES-256-CBC stream-start-bytes verifier), alongside the existing
  KDBX4. Cross-validated against a genuine KDBX3 fixture accepted by both
  KeePassXC 2.7.6 and pykeepass 4.2.0.
- **Office 97/2000 RC4 40-bit key attack** (`xcrack office-keyattack FILE`): the
  Elcomsoft "Thunder Tables" weakness — sweep the 2^40 trunc keyspace against the
  document verifier to recover the key regardless of password length/complexity
  (shardable with `--shard i/N`, parallel across cores, resumable). Office
  XP/2003 CryptoAPI RC4 is correctly excluded (160-bit intermediate). The
  `xcrypto/scheme/officebinary` verifier/searcher is cross-validated against the
  msoffcrypto-tool reference vector.
- **GPU PBKDF2-HMAC-SHA256 and -SHA512 kernels** in the opt-in OpenCL tier
  (RAR5-class and SQLCipher-v4-class), beyond the existing SHA-1. The
  `xfileformats.AccelKDF` seam gained a PRF selector and the engine dispatches to
  the matching kernel. Every variant is validated byte-for-byte against the Go
  reference at startup.
- **Multi-device OpenCL + batch-size autotune**: the GPU tier now builds a queue
  and kernel per device and splits a batch across devices concurrently, and
  autotunes the per-dispatch batch size (exposed via `accel.BatchTuner`, used by
  the engine; `Options.AccelBatch` overrides).
- **Automatic cost-aware recovery queue** (`--cost-queue`, config
  `search.cost_queue`): benchmark each input file's verify rate and attack the
  fastest/weakest schemes first across a pile of files.
- **Inspection / estimation modes** on the crack command (no cracking):
  `--stdout` prints the assembled candidate stream (hashcat `--stdout`);
  `--keyspace` prints the candidate keyspace size; `--benchmark`/`-b` measures
  the per-file verify rate (candidates/sec); `--estimate` combines keyspace ×
  rate into a time-to-crack. `--limit N` caps `--stdout`/`--keyspace`.
- `--progress` now shows a true percent and a candidate-rate ETA for a single
  target whose keyspace is known (e.g. a mask), falling back to the per-file
  reporter otherwise.

## PR #15 — 2026-10-17 — Distributed cracking, challenge/Markov/time-limit CLI, Swedish list, RAR5

### Added
- **Distributed cracking across many xcrackd servers** (`pkg/cluster`): xcrack
  orchestrates a fleet of workers over the HTTP API. *Collective* mode throws
  every server at one file on disjoint candidate batches (first hit wins, the
  rest are cancelled); *partition* mode splits servers into groups that take
  different files. Server set and allocation are settable from the command line
  (`--server URL[@GROUP]`, `--cluster-mode`, `--cluster-batch`,
  `--cluster-allow-defaults`, `--cluster-per-request`) or the config `cluster`
  block. A worker only ever reports whether a candidate it was handed worked, so
  it cannot inject a false positive. The `xcrackd` API gained a multipart
  request shape (`file` + `wordlist` parts), a server-side `shard=I/N`, and a
  `max-duration` hint.
- **Embedded Swedish-targeted wordlist** (`--swedish`, `candidates.Swedish`):
  ~31k curated, language-specific entries (common words, names, cities, clubs,
  holidays + typical mutations), ordered most-probable-first, generated
  reproducibly by `gen_swedish.go`.
- **Challenge-envelope CLI**: `xcrack export-challenge` emits the portable JSON
  challenge envelope for an external cracker; `xcrack --resume-from` imports a
  recovered-password envelope and tries it first. (Previously the envelope was a
  library-only capability.)
- **Markov wordlist ordering** (`--order markov`): reorder the wordlist
  candidates so the statistically likeliest words are tried first
  (`candidates.ByScore`), distinct from `--markov` generation.
- **`--time-limit`**: a clearly-named per-file budget to abandon a stuck search
  and move on; a deadline is now a graceful give-up (locked, exit 1), not an
  error.
- **RAR5 fast password verification** (`xcrypto/scheme/rar5`): uses the 8-byte
  check value stored in the RAR5 header to reject a wrong password after key
  derivation alone — no decrypt/decompress — reading the iteration count from
  the header. Cross-validated against the `rar` CLI for `-hp` and `-p` archives.

### Changed
- The GPU PBKDF2-HMAC-SHA1 tier is wired into the **live crack loop**: WinZip-AES
  and encrypted DMG batch their keyspace sweep onto the device (opt-in `xcrackd
  --gpu`), re-checked by the CPU verifier, with transparent CPU fallback.
- Docs: added this changelog and `docs/REFERENCES.md`.

## PR #14 — 2026-10-17 — GPU live loop, on-disk DMG, CLI feature wiring

### Added
- GPU PBKDF2 wired into the live crack loop (`AccelKDF` seam, `Options.Accelerator`).
- On-disk encrypted DMG (`encrcdsa` v2) parsed and cracked directly (AES-128/256),
  validated against real macOS images.
- CLI reach for existing library features: `--combinator-*`, `--increment`,
  `--markov`; `--as sqlcipher` force-format; MS Access detection; encrypted
  Publisher/Visio/Project via the shared OOXML path.

## PR #13 — 2026-10-16 — Candidate sources, adaptive/distributed, streaming, DMG, GPU tier

### Added
- WinZip-AES `$zip2$` hash-line emitter (hashcat `-m 13600`).
- Breach-corpus (`--breach`) and password-spray (`--spray`) candidate sources.
- Adaptive scheduling (`--adaptive`): corpus-wide promotion + smallest-file-first.
- Disk-streaming of large entries (spill above a threshold).
- Keyspace sharding (`--shard I/N`) for manual distribution.
- Encrypted DMG recovery via the `dmg2john` `$dmg$` line (v1/v2), John-vector validated.
- Opt-in OpenCL GPU tier for `xcrackd` (`-tags opencl`), self-tested against the CPU reference.
- PRINCE, toggle-case, keyboard-walk generators.

## PR #11 — 2026-10-16 — CI determinism, hybrid + hash-line attacks, ODF-GCM & KeePass

### Added
- `$office$` / `$pdf$` hash-line emitters (hashcat / John), hashcat-cross-validated.
- Hybrid attack (`--hybrid-append` / `--hybrid-prepend`).
- ODF 1.3 authenticated AES-256-GCM.
- KeePass KDBX4 (`.kdbx`) with an in-tree Argon2d, validated against `argon2` / pykeepass.

### Changed
- Fuzz and qpdf CI gates made deterministic (replay committed corpora / vectors).

### Fixed
- PDF `rebuild` xref-table DoS (bounded object numbers).

## PR #12 — 2026-10-16 — PDF R6 fix

### Fixed
- Off-by-one in the ISO 32000-2 Algorithm 2.B (PDF AES-256 / R6) hash loop, which
  caused intermittent user-password verification failures; validated 300/300
  against qpdf.

## PR #10 — 2026-10-16 — iWork, password-hint candidates, example configs

### Added
- Apple iWork (Pages/Numbers/Keynote) passphrase recovery, reversed and validated
  against real 14.5 samples.
- Password-hint candidate derivation (`--hint`, `--hint-rules`) from embedded hints
  (iWork `.iwph`, ZIP comment).
- Example config files in `config/`.

### Fixed
- Re-detect-after-decrypt picked a non-container format sharing the ZIP magic,
  stopping decomposition; now picks the best container.
- CFB DIFAT sector-chain walk bounded by the file's sector count.

## PR #9 — 2026-10-16 — Sample set

### Added
- `samples/` demo set with a reproducible generator; every passphrase is `opensesame`.

## PR #8 — 2026-10-16 — ZipCrypto known-plaintext + key/data-store formats

### Added
- Full in-tree Biham–Kocher ZipCrypto known-plaintext key recovery (`xcrack kp`),
  with a ~34× two-step fiber speedup and an external `bkcrack` offload, cross-validated.
- OpenSSH keys, encrypted PEM/PKCS#8, JKS, PKCS#12, PuTTY `.ppk`, SQLCipher —
  each cross-validated against the real tool.
- Weir-style PCFG generator (`--pcfg`).

## PR #7 — 2026-10-16 — Search engine depth

### Added
- Full hashcat rule engine; context/association candidates (`--context`);
  per-format fast-reject; checkpoint/resume (`--checkpoint`); Prometheus metrics;
  audit hook; single-password ergonomics, potfile, find-all, progress, logging.

## PR #4 — 2026-10-16 — Service tier + GPU-offload plumbing + new formats

### Added
- `xcrackd` HTTP service and `pkg/api`; challenge export/import; Markov ordering
  primitive; pluggable live candidate provider.
- `age` (scrypt), symmetric OpenPGP (`gpg -c`), header-encrypted 7z/RAR —
  each cross-validated against the real CLI.

## PR #3 — 2026-10-15 — Legacy MS Office

### Added
- `.doc/.xls/.ppt` decryption (RC4 CryptoAPI, Office 97/2000 RC4, XOR), RC4 CryptoAPI
  cross-validated byte-for-byte against gold-standard decrypted documents.
- `Registry.DetectAll` ranked detection with graceful fallback.

## PRs #1–#2 — 2026-10-15 — MVP + Phase 2 foundation

### Added
- Three-module layout (xcrypto / xfileformats / xcrack); recursive decomposition
  engine; ZIP (ZipCrypto + WinZip-AES), OOXML, PDF; pattern engine (masks + rules);
  candidate sources; CLI + renderers; fuzz / bomb / known-answer / race gates;
  `examples/impex-embed`. Phase-2 breadth: ODF, tar/gzip/bzip2/xz/7z/rar,
  `.eml` extraction.
