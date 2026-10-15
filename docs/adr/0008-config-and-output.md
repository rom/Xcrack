# ADR-0008 — Configuration precedence and output handling

Status: Accepted · Serves: QA-8, QA-9, CON-3, CON-7

## Context
Xcrack is driven both as a library (Impex sets `Options`) and a CLI (flags +
config file + env). Output must serve machines (Impex/tooling) and humans, and
must not leak recovered secrets into logs.

## Decision
- **Config precedence:** flags > environment (`XCRACK_*`) > config file (YAML) >
  built-in defaults. The CLI resolves these into the same `Options` the library
  takes (CON-3 parity).
- **Config format:** YAML.
- **Output renderers:** `text` (human), `json` (one object), `jsonl` (one node/
  file per line for streaming). When `--out` is set, write the decrypted tree to
  disk plus a `manifest.json` describing it.
- **Results vs logs:** recovered passwords and decrypted content go to the
  **result** (and `--results-file`); the **logger redacts passwords by default**
  and never emits decrypted content. An optional `--audit-log` records actions
  (not secrets) for DFIR.
- **Exit codes:** `0` something unlocked, `1` nothing unlocked, `2` error.

## Options considered
1. **TOML / JSON config.** Fine; YAML chosen for readability of nested limits/
   patterns and because it carries the pattern wrapper naturally. Low-stakes,
   reversible.
2. **Single combined stdout stream for logs + results.** Rejected — mixing secrets
   into logs violates QA-8; separation is explicit.

## Consequences
- **+** One options model for library and CLI (CON-3); predictable overrides.
- **+** Machine-readable output for Impex; secret hygiene by construction (QA-8).
- **−** YAML parsing is one dependency (vetted, pure Go); acceptable under CON-5.
- **−** Three renderers to maintain; covered by the parity and golden tests.
