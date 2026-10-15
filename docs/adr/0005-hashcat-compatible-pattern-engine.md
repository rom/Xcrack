# ADR-0005 — hashcat-compatible mask/rule pattern engine

Status: Accepted · Serves: FR-7, QA-10

## Context
The user asked for "pattern files that specify how to permute password tests."
A mature ecosystem of mask and mangling-rule files already exists (hashcat, John
the Ripper). We can adopt an existing syntax or invent our own.

## Decision
Implement a **hashcat-compatible** pattern engine natively in Go:
- **Masks:** `?l ?u ?d ?s ?a ?b` + user charsets `?1..?4`.
- **Rules:** a documented subset of hashcat mangling rules for the MVP
  (`: l u c $x ^x r d s tN TN { }`), extensible later.
A thin **YAML wrapper** expresses masks/rules readably and bundles them in the
config file, compiling down to the same engine.

## Options considered
1. **hashcat-compatible (chosen).** Users reuse existing rule/mask files;
   familiar syntax; well-specified.
2. **John the Ripper rule syntax.** Also mature; less commonly the lingua franca
   for masks; rejected to avoid supporting two rule dialects.
3. **Bespoke DSL only.** Full control but zero ecosystem reuse and a learning
   curve for operators. Rejected as the primary syntax; the YAML wrapper gives
   readability without abandoning compatibility.

## Consequences
- **+** Operators drop in existing `.rule`/mask files (FR-7).
- **+** Masks have a computable keyspace size → good progress/ETA and up-front
  bounding (ties to `MaxCandidates`).
- **−** We must track hashcat rule semantics for the subset we claim to support;
  the subset is documented explicitly to avoid "almost-compatible" surprises.
- Candidate generation lives in the engine (`pkg/xcrack/patterns`), not in
  Xfileformats, preserving the library's policy-free boundary
  ([ADR-0002](0002-standalone-xfileformats-library.md)).
