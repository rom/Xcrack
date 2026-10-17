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
