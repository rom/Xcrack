# Xcrack — MVP Definition

> **Status (implementation in progress).** The reusable crypto/cracking module
> (Xcrypto), ZIP (ZipCrypto + WinZip AES), **OOXML MS Office (agile + standard)**, **PDF** (RC4/AESV2/AESV3),
> the **hashcat-compatible pattern engine**, **disk-spill**, **fuzz + bomb
> corpora with CI**, **two-axis concurrency (parallel sibling entries)**, recursive decomposition, the result
> tree, budgets, and the CLI are **implemented and tested**. Still outstanding
> for the MVP: PDF cross-validation against a reference encoder (no encoder was
> available in this environment). See the repository README's Status
> section for the live checklist.

The MVP proves the architecture end-to-end on a vertical slice: the standalone
**Xfileformats** library, the **Xcrack** engine with recursion and the two-axis
pool, and a usable CLI — across the first tier of formats — with hostile-input
safety in place from day one.

## 1. MVP goal (one sentence)

*Given an untrusted, possibly nested, possibly encrypted file and a set of
candidate passwords, produce a verified tree of decrypted/extracted content plus
the passwords that unlocked each layer — safely, within bounded resources, and
callable both as a Go library (as Impex will) and from the CLI.*

## 2. In scope

### Formats (first tier, in build order)
1. **ZIP** — ZipCrypto (legacy) and WinZip AES-128/192/256. *(Also the first
   container type.)*
2. **OOXML MS Office** — `.docx/.xlsx/.pptx` agile encryption (AES + SHA-512
   KDF) and standard encryption (AES-128 + SHA-1).
3. **PDF** — RC4 40/128-bit, AESV2 (128), AESV3 (256); user **and** owner password.

> Legacy MS Office, ODF, and the remaining archive formats (tar/gzip/bzip2/xz/
> 7z/rar/eml) are **post-MVP** ([roadmap](roadmap.md)), but the interfaces and
> the registry are designed for them now.

### Container / recursion
- ZIP unpacking and **recursive decomposition** across ZIP layers (and into
  OOXML/PDF as leaves by default).
- `--explode-documents` opt-in wired through (even if only ZIP-based OOXML
  explosion is realised first).
- Full budget enforcement: depth, total bytes, node count, per-entry ratio,
  cycle detection.

### Engine
- `CandidateSource`: explicit passwords, wordlist files (+ gzip, + stdin), the
  embedded default list, and in-memory programmatic injection.
- Pattern engine: masks + a core rule subset (hashcat-compatible), plus the YAML
  wrapper.
- Two-axis concurrency (`Workers`, `FileConcurrency`) under a global semaphore;
  reusable `Pool`.
- Password promotion.
- `context` cancellation + per-file timeout.
- Result tree with per-node password + content; `OnProgress`/`OnFound`.

### CLI
- Flags: `--source`, `--out`, `--wordlist`, `--password`, `--config`,
  `--pattern`, `--format`, `--log-level`, `--results-file`, and the MVP
  concurrency subset (`--workers`, `--file-jobs`, `--timeout`, resource caps).
- `xcrack identify` (detect only) and `xcrack version`.
- Output renderers: `text`, `json`, `jsonl`; manifest when `--out` is set.
- Exit codes 0/1/2.

### Safety & quality (non-negotiable in MVP)
- `recover()` boundaries; no panic escapes.
- Fuzz tests on `Detect`/`Probe`/`Entries` for the tier-1 formats.
- Known-answer vectors for each KDF/cipher.
- Golden round-trip corpus for every supported variant.
- `-race`-clean batch runs.

## 3. Out of scope for MVP

- Legacy MS Office, ODF, 7z, RAR, XZ, bzip2, tar, eml (designed-for, not built).
- GPU, distributed, online attacks (never — see ASR non-goals).
- Checkpoint/resume (FR-11), throttle, `--max-duration`, `--batch-size`
  (phase 2).
- Full document explosion beyond OOXML.
- BitLocker/VeraCrypt/full-volume.

## 4. Acceptance criteria

The MVP is done when all of the following hold:

| # | Criterion |
| - | --------- |
| A1 | Xfileformats builds and tests as a standalone module with **no dependency** on `xcrack`. |
| A2 | For each tier-1 format and each of its in-scope variants, a known-password sample is detected, verified, and decrypted correctly (golden corpus green). |
| A3 | A 3-level nested sample (encrypted ZIP → encrypted `.docx` → encrypted ZIP → text) is fully decomposed; the result tree reports the correct password and content at every node. |
| A4 | Password promotion demonstrably reduces candidates tested on a reused-password nest (metric asserted in a test). |
| A5 | Each bomb-corpus input (deep nest, zip bomb, quine) is handled within the configured limits; peak memory stays bounded; the run terminates and reports limit nodes. |
| A6 | Fuzzing the tier-1 `Detect`/`Probe`/`Entries` for a fixed budget produces **zero** panics / OOMs / hangs. |
| A7 | The same inputs produce identical `Result` from the library call and the CLI (parity test). |
| A8 | A `Pool` processes a batch of N files from M goroutines with total live workers never exceeding `MaxProcs` (asserted). |
| A9 | Recovered passwords never appear in default-level logs (asserted); they appear in the result and results-file. |
| A10 | `go test ./... -race` passes for both modules; `go vet` clean; CI green on linux/amd64 and linux/arm64. |

## 5. Demonstration scenarios

- **Impex embed demo:** a small Go program builds a `Pool`, feeds a directory of
  mixed encrypted samples with an in-memory candidate list, and prints the trees —
  the canonical embedding example that ships in `examples/`.
- **CLI triage demo:** `xcrack -s sample.zip -w rockyou-small.txt -p infected -o ./out --format json`
  decrypts and writes the tree + manifest.
- **Bomb demo:** `xcrack identify bomb.zip` and a bounded `xcrack -s bomb.zip`
  showing limits firing cleanly.

## 6. Rough effort shape (not a schedule)

1. Scaffold both modules, interfaces, registry, budget/limits, result tree.
2. ZIP (ZipCrypto + AES) as the first Encrypted+Container; prove recursion + pool.
3. OOXML, then PDF.
4. Pattern engine (masks + rule subset) + YAML wrapper.
5. CLI + renderers + examples.
6. Harden: fuzz, bombs, race, golden corpus, parity.
