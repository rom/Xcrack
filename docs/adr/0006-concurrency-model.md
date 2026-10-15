# ADR-0006 — Two-axis concurrency with a shared global cap

Status: Accepted · Serves: QA-5, QA-3, FR-10

## Context
Impex scans many files, each typically with a small candidate set; sometimes one
file needs a large search. Naive "one knob" concurrency either underuses cores on
batches or overuses them within a file — and either can spawn unbounded
goroutines inside the host.

## Decision
Expose **two orthogonal concurrency axes** and bound their product with a single
global semaphore:
- **`Workers`** — candidate-test goroutines *within* one file (the KDF grind).
- **`FileConcurrency`** — files/entries processed concurrently.
- **Invariant:** live workers = `FileConcurrency × Workers ≤ MaxProcs`.
A reusable, bounded **`Pool`** holds the semaphore and buffers; a long-running
Impex service constructs it once and feeds files through `Pool.Process`, which is
safe for concurrent use.

## Options considered
1. **Single `--threads` knob.** Simple but conflates the two axes; can't tune
   "many files, few candidates each" vs "one file, huge keyspace." Rejected.
2. **Unbounded goroutine-per-file / per-candidate.** Simplest code; unbounded
   resource use — unacceptable in an embedded context. Rejected.
3. **Two axes + global semaphore + reusable pool (chosen).**

## Consequences
- **+** Predictable resource envelope at any batch size (QA-5); good scaling both
  across files and within a file.
- **+** `Pool` matches a long-running service's lifecycle (FR-10, QA-3).
- **−** Slightly more complex scheduler; two knobs to document and default well
  (defaults: both `NumCPU`, `MaxProcs = NumCPU`).
- Backpressure via bounded channels; `batch-size` hand-off (phase 2) amortises
  overhead for cheap KDFs.
