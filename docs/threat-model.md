# Xcrack — Threat Model

Xcrack's normal input is **hostile by design**: as a malware pre-processor it is
fed exactly the files attackers craft to evade and attack scanners. The threat
model therefore centres on surviving malicious *input*, not on defending a
network service. This document follows a lightweight STRIDE-informed structure.

## 1. Context, assets, and trust boundaries

```
   TRUSTED                                   │   UNTRUSTED
                                             │
  Impex service  ──builds Pool, injects──▶   │
  (caller)          candidates, ctx          │
                                             │   ┌──────────────┐
  Xcrack engine  ◀── file bytes ─────────────┼── │ input file   │  ← attacker-controlled
  (our code)     ── result tree ──▶ Impex    │   │ (+ all nested │
                                             │   │  layers)      │
  Xfileformats   ── parses untrusted ───────▶│   └──────────────┘
  (our code)        bytes                    │
                                             │   candidate wordlists / pattern files
                                             │   (semi-trusted: operator-supplied)
```

**Assets to protect:**
- **A1 — Host availability/resources** (CPU, memory, disk, file descriptors) of
  the Impex host. Primary asset.
- **A2 — Integrity of the Impex process** (no code execution, no corruption).
- **A3 — Confidentiality of recovered secrets** (passwords, decrypted content).
- **A4 — Correctness of results** fed to the scanner (no silent wrong content).

**Trust boundary:** every byte of the input file — and of each decrypted/
unpacked layer — crosses from untrusted to our parsers. Candidate wordlists and
pattern files are semi-trusted (supplied by the operator/Impex config), but are
still treated as untrusted *data* (bounded, validated).

## 2. Threats and mitigations

### T1 — Denial of service via resource exhaustion (STRIDE: DoS) — **primary**
Crafted inputs try to exhaust the host:
- **Decompression / "zip" bombs** (tiny file → petabytes). → `MaxTotalBytes`
  (global budget), `MaxEntrySize`, `MaxRatio` per-entry ratio cap, and bounded
  streaming decompression that stops at the cap.
- **Deeply nested archives** (archive-in-archive ×10⁴). → `MaxDepth` ceiling.
- **Fan-out bombs** (millions of tiny entries). → `MaxNodes` cap.
- **Zip quines / cyclic nesting** (a file that contains itself). → content-hash
  **cycle detection**; a repeat hash prunes the branch.
- **CPU exhaustion via KDF abuse** (headers claiming billions of iterations). →
  sane `KDF` parameter ceilings during `Probe`; per-file `Budget`/`timeout`.
- **Memory spikes from huge declared sizes.** → never trust declared sizes;
  bounded `io.ReaderAt`; allocate against actual, capped reads; spill to disk
  above `SpillThreshold`, itself counted against the global byte budget.
- **Goroutine/FD explosion at batch scale.** → single global semaphore
  (`MaxProcs`); bounded channels; pooled buffers.

### T2 — Remote code execution via content interpretation (STRIDE: Elevation) — **critical**
A decrypted file is a weaponised document/exploit. If Xcrack *opened* it with a
real application (Office, LibreOffice, a PDF renderer), that would detonate.
- **Mitigation (architectural):** Xcrack **never** executes or renders content.
  It only derives keys and moves bytes — a pure-Go reimplementation with **no
  external process** ([ADR-0001](adr/0001-pure-go-no-external-binaries.md)). This
  is the main reason "shell out to LibreOffice" was rejected.

### T3 — Parser memory-safety faults (STRIDE: DoS/Elevation)
Malformed crypto headers / container metadata trigger panics, slice OOB, or
pathological allocation in our parsers.
- **Mitigations:** Go's memory safety (no buffer overflows); a `recover()`
  boundary around every `Detect`/`Probe`/`Verify`/`Decrypt`/`Entries` call that
  converts a panic into a per-node `StatusError` (scan continues); defensive
  bounds checks; **fuzzing** every parser with the invariant *no panic / bounded
  memory / terminates*; no `unsafe`, no cgo in format parsers.

### T4 — Path traversal / filesystem escape on extraction (STRIDE: Tampering)
A container entry named `../../etc/cron.d/x` tries to write outside `--out`.
- **Mitigations:** entry paths are normalised and validated; any `..` or absolute
  component is rejected or sanitised; extraction is confined to the output root
  via `filepath` containment checks; symlinks in archives are never followed or
  recreated; the library default returns content as streams (no implicit writes).

### T5 — Secret leakage (STRIDE: Information disclosure)
Recovered passwords or decrypted (malicious) content leak via logs, temp files,
or error strings.
- **Mitigations:** redacting logger — passwords never logged at default levels;
  confined to `Node.Password`/`Found`; temp spill files created `0600` in a
  per-run dir and securely removed; errors scrubbed of secret material;
  decrypted content not persisted unless the caller sets `--out`.

### T6 — Wrong/garbage results (STRIDE: Tampering/Spoofing of output)
A near-miss password yields plausible-but-wrong plaintext, or a format quirk
makes Xcrack mislabel content.
- **Mitigations:** decryption is accepted only on a **verified** format verifier
  match (QA-6); known-answer + golden round-trip tests; detection by content
  magic, not extension; ambiguous detection reported, not guessed.

### T7 — Malicious candidate/pattern/config input (STRIDE: DoS)
A giant or adversarial wordlist / pattern expands into an unbounded keyspace, or
config sets limits to unsafe values.
- **Mitigations:** candidate streaming (never fully materialised); `MaxCandidates`
  cap; mask keyspace computed up-front and bounded; config values validated
  against hard safety floors/ceilings the operator cannot disable below a floor.

### T8 — Supply-chain / dependency risk (STRIDE: Elevation)
A third-party decompression/crypto dependency carries a vulnerability.
- **Mitigations:** stdlib-first; minimal, vetted, pure-Go dependencies pinned and
  checksummed (`go.sum`); `govulncheck` in CI; explicit format registry so a
  consumer can disable any parser they don't need, shrinking attack surface.

## 3. Residual risks & assumptions

- **Assumption:** the caller (Impex) is trusted and sets sane limits; Xcrack
  enforces hard floors but cannot protect against a caller that disables all
  budgets on purpose.
- **Residual:** an as-yet-unknown algorithmic complexity bug in a parser could
  still burn CPU up to the `timeout`/`Budget`; the per-file deadline bounds the
  blast radius.
- **Residual:** extremely slow legitimate KDFs (by design) mean a large-keyspace
  search is inherently slow; this is a performance characteristic, not a defect —
  the budget model turns it into a bounded "undetermined" result.
- **Out of model:** host OS hardening, container escape, and Impex's own network
  exposure are the responsibility of the deployment, not Xcrack.

## 4. Security testing (implemented)

- **Fuzz targets** on every parser exposed to hostile input -- the pattern
  engine, the OOXML EncryptionInfo parser, the CFB reader, ZIP central-directory
  parsing, the OOXML/PDF format probes, the PDF decrypt-rebuild scanner, and the
  whole engine pipeline (`FuzzProcess`). Each asserts the invariant *no panic,
  bounded work, terminates*. `scripts/fuzz.sh` runs them all; `go test` replays
  the committed seed/regression corpora. Fuzzing already found and fixed a real
  DoS/crash: an out-of-range slice on a crafted PDF with a short `/O` or a huge
  `/Length` (now clamped), and an unbounded agile `spinCount` (now capped). The
  crasher is kept as a regression seed.
- **Bomb corpus** (`bomb_test.go`): a decompression bomb (cut off at
  `MaxEntrySize`), a fan-out bomb (bounded by `MaxNodes`), the cumulative
  byte-budget (`MaxTotalBytes`), and a cycle/quine case (ancestor-hash
  detection) -- each asserting bounded resource use.
- **CI** (`.github/workflows/ci.yml`): build, `go vet`, `gofmt` check,
  `go test -race` across all three modules (which also replays the fuzz seeds),
  a bounded fuzz smoke run, and `govulncheck` (non-blocking).
- Golden round-trip + known-answer vectors remain the regression guards for
  QA-6 (no false-positive unlocks).
