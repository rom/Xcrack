# ADR-0004 — Hostile-input safety and resource budgets

Status: Accepted · Serves: QA-1, QA-5, CON-6 · Realises much of the [threat model](../threat-model.md)

## Context
Xcrack's normal input is attacker-crafted. Recursive decompression is the
classic home of zip bombs, quines, deep nesting, and fan-out bombs; malformed
crypto headers invite parser faults. Running inside Impex, Xcrack must never
exhaust or crash the host.

## Decision
Enforce a **global budget** across the whole decomposition tree, not per file,
plus per-parser safety:
- `MaxDepth` (default 32), `MaxTotalBytes` (cumulative decompressed budget),
  `MaxNodes`, `MaxEntrySize`, `MaxRatio` (per-entry compression ratio),
  `MaxCandidates`, per-file/whole-run time `Budget`.
- **Cycle detection** by content hash (defeats quines/self-containing files).
- **Bounded readers** everywhere; declared sizes are never trusted.
- Intermediates spill to a locked temp dir above `SpillThreshold`, counted
  against `MaxTotalBytes`, wiped on completion.
- A `recover()` boundary around every format call converts a parser panic into a
  per-node error; the scan continues.
Limits have **hard safety floors** a caller cannot disable below.

## Options considered
1. **Per-file limits only.** Insufficient: a tree of individually-small files can
   still sum to a bomb. Rejected.
2. **Global tree budget + per-parser guards (chosen).**
3. **External sandbox (seccomp/container) instead of in-process limits.** Useful
   defence-in-depth for deployment, but cannot be relied on for an *embedded
   library*; in-process budgets are mandatory regardless.

## Consequences
- **+** Bounded memory/CPU/disk regardless of input or batch size (QA-1, QA-5).
- **+** One accounting model shared by all formats and the recursion.
- **−** A legitimate very-large nested archive may hit limits and yield partial
  results with `StatusLimitExceeded` nodes — accepted and reported, not silent.
- **−** Content-hash cycle detection costs a hash per node — cheap relative to
  KDFs.
