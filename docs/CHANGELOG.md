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
