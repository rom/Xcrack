# Xcrack — Roadmap

Phased plan beyond the [MVP](mvp.md). Phases are ordered by dependency and value;
they are not date-bound. Each phase leaves `main` releasable.

## Phase 0 — Foundations (part of MVP)
- Two modules scaffolded; `Format`/`Encrypted`/`Container`/`Explodable`
  interfaces; explicit registry; `Challenge`.
- Budget/Limits accounting; result `Node` tree; `recover()` boundaries.
- Two-axis scheduler + global semaphore + reusable `Pool`.
- Logging (redacting), `context` plumbing, `OnProgress`/`OnFound`.

## Phase 1 — Tier-1 formats + recursion (MVP)
- ZIP (ZipCrypto + WinZip AES) as first Encrypted + Container → proves recursion.
- OOXML Office (agile + standard). PDF (RC4 + AESV2 + AESV3, user + owner).
- CandidateSource (explicit / wordlist / gzip / stdin / default list / in-memory).
- Pattern engine: masks + core rule subset + YAML wrapper. Password promotion.
- CLI (`xcrack`, `identify`, `version`) + text/json/jsonl renderers + manifest.
- Safety gate: fuzz, bombs, known-answer, golden corpus, race, parity.
- `examples/impex-embed` reference integration.

## Phase 2 — Format breadth + ergonomics
- **Formats:** legacy MS Office (`.doc/.xls/.ppt`, CryptoAPI/RC4); ODF (Blowfish-CFB
  legacy + AES-GCM modern); archive unpackers: tar, gzip, bzip2, xz/lzma, 7z, rar;
  `.eml`/MIME attachment extraction.
- **Document explosion:** full OOXML/OLE part decomposition behind
  `--explode-documents`.
- **Concurrency ergonomics:** `--batch-size`, `--max-duration`, `--throttle`,
  `--input-list` streaming.
- **Resilience:** checkpoint/resume for long single-file searches (FR-11).

## Phase 3 — Smarter search
- Combinator and hybrid attack modes.
- Markov / statistical candidate ordering; frequency-weighted wordlists.
- Challenge export/import (interop with `*2john`-style workflows) so probing and
  testing can be split across processes/machines.
- Per-format "fast reject" heuristics to skip hopeless candidates cheaply.

## Phase 4 — Scale & operations
- Optional distributed candidate sharding (coordinator + workers) — still CPU,
  still offline. (Explicitly a later, opt-in capability, not core.)
- Metrics endpoint/hooks (Prometheus-style counters) for embedding telemetry.
- Pluggable candidate providers (e.g. Impex supplies a live per-scan provider).

## Phase 5 — Extended formats (demand-driven)
- KeePass databases; age; GPG symmetric; Apple iWork; RAR5 specifics.
- Full-volume formats (BitLocker/VeraCrypt/LUKS/FileVault) — large, separate
  effort; gated on real demand and a dedicated threat review.

## Cross-cutting, ongoing
- Expand fuzz corpus and bomb corpus with every new format.
- `govulncheck` + dependency review each release.
- Keep CLI/library parity (CON-3) as an enforced test.
- Documentation kept in lock-step (ADR per significant decision).

## Explicitly out (all phases)
- GPU/OpenCL cracking.
- Any network/online/remote attack.
- Cryptographic weakening/exploitation of sound algorithms.
- Executing or rendering file content.
