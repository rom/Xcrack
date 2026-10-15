# ADR-0002 — Split format knowledge into the standalone Xfileformats library

Status: Accepted · Serves: QA-4, QA-10, CON-4

## Context
Format knowledge (detect / probe / verify / decrypt / unpack) is valuable beyond
cracking — other internal tools want "what is this, is it encrypted, unlock with
*this* password, list entries." Bundling it inside the cracking engine would
force those tools to depend on candidate generation, concurrency, and recursion
policy they don't want.

## Decision
Factor all format knowledge into a **separate Go module**,
`github.com/rom/xfileformats`, that is **policy-free**: it knows nothing about
candidate lists, search strategy, concurrency, or recursion. The engine
(`github.com/rom/xcrack`) imports it. Both modules live in one repository.

## Options considered
1. **One module, internal packages.** Simplest, but no clean reuse boundary and
   easy for policy to leak into format code.
2. **Separate module, same repo (chosen).** Clean import boundary and
   independent versioning, while keeping one place to develop/test/release.
3. **Separate repository.** Maximum independence, but premature overhead now;
   the same-repo split is trivially promotable to its own repo later.

## Consequences
- **+** Any tool can import Xfileformats alone (QA-4). Format code stays honest —
  if it tried to reach into candidate/recursion concepts, it wouldn't compile.
- **+** New formats are added in one module without touching the engine (QA-10).
- **+** Independent semver for the reusable library.
- **−** Two `go.mod` files and a `replace`/workspace during local development
  (mitigated with a `go.work`).
- Formats register **explicitly** (not via `init()`), so a consumer chooses which
  parsers are exposed to hostile input (supports the threat model).
