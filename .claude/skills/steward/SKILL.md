---
name: steward
description: >-
  Repo-specific guidance for stewarding a Xcrack pull request to green — how to
  validate a change before pushing, which conventions to respect, and how
  proactive to be. Read this (from the PR's head branch) before acting on a CI
  failure or a review comment on a Xcrack PR.
---

# Stewarding a Xcrack PR

This is repository content: conventions and how-proactive guidance for driving a
Xcrack PR to green. It refines the host's generic drive-to-green rules for *this*
repo; it does **not** override any rule stated there as "never", and it does not
let you approve or merge — a human (the repo owner) merges.

## Engineering standards (the bar every change meets)

Claude is a world-class programmer with extensive experience in developing
security software — as strong at debugging, bug-finding and refactoring as at
writing new code — and a world-class cryptologist and cryptanalyst with long,
unique experience in the field. Hold the work to that bar:

- **Targeted and focused.** Each change is well-scoped and solves the actual
  problem — no incidental widening of a PR, no speculative abstraction.
- **Resilient.** Every return value is checked and every error is handled
  (never silently dropped — handle, wrap with context, or deliberately ignore
  with a comment saying why). Guard the boundaries: untrusted input, size and
  resource limits, concurrency, and overflow.
- **Tested.** All code carries unit tests; keep code-coverage tests meaningful,
  and add security tests (hostile-input/fuzz, false-positive, and
  resource-exhaustion cases) wherever the change touches a parser, a verifier,
  or a resource bound. A fix lands with the test that would have caught the bug.
- **Documented as it is written.** Docs are written alongside the code, not
  after — update the exported doc comments and the relevant files under `docs/`
  (and `--help`/config) in the same change, so the docs never lag the behaviour.

These are the house standards; the repo-specific rules below say how to apply
them here.

## Repository shape

Three Go modules joined by `go.work` at the repo root:

- `xcrypto/` — cryptographic schemes and the candidate/attack engines (no file I/O).
- `xfileformats/` — format detection, parsing and decryption wrappers over `xcrypto`.
- `xcrack/` — the engine (`pkg/xcrack`), the `xcrack` CLI (`cmd/xcrack`), the
  `xcrackd` server (`cmd/xcrackd`), the HTTP API (`pkg/api`), the GPU tier
  (`pkg/accel`), the distributed client (`pkg/cluster`), and `examples/`.

The default branch is **`rom`**; feature work lands on a `claude/**` branch and
merges into `rom`. After a PR merges, restart the feature branch from the updated
`origin/rom` rather than stacking new commits on merged history.

## Validate before every push (this is what CI runs)

CI has two required jobs, both on `ubuntu-latest`:

1. **`build · vet · race tests`** — `go build`, `go vet`, a gofmt check, then
   `go test -race` across all three modules (also replays the fuzz seed corpora).
2. **`fuzz corpus (deterministic)`** — `go test -run='^Fuzz' ./...` over the
   committed seed corpora (no random exploration, so it cannot flake).

Reproduce both locally from the repo root before pushing:

```sh
make fmt-check        # gofmt -l over the three modules; CI fails on any output
make vet              # go vet ./xcrypto/... ./xfileformats/... ./xcrack/...
make race             # go test -race across all three modules  (~1–2 min)
# the fuzz gate:
go test -run='^Fuzz' ./xcrypto/... ./xfileformats/... ./xcrack/...
```

`make check` = `fmt-check` + `vet` + `race` in one go. For a tight fix loop run
the changed package first (`go test -race ./xcrack/pkg/xcrack/...`), but run the
**full `make check` and the fuzz gate before you push** — a push that reds CI
costs a cycle. gofmt every file you touch (`gofmt -w`).

CI also installs `qpdf` and `p7zip-full` (and best-effort `rar`/`unrar`) for
format cross-validation; tests that need a missing tool **skip**, so a local run
without them is not proof. `govulncheck` runs but is non-blocking — a vuln
advisory is not a red gate.

## Conventions that must hold

- **ADR 0001 — the default build is pure-Go and cgo-free.** Never add cgo or a
  non-pure-Go dependency to the default build. The OpenCL GPU tier lives in
  `xcrack/pkg/accel/*_opencl.go` behind `//go:build opencl` and **CI never builds
  it**. Therefore a change to the `-tags opencl` files is unverifiable by CI and
  usually unverifiable in a cloud session (no GPU): do **not** blind-edit it to
  satisfy a review or a hunch. If a finding is in that code, leave it for a GPU
  host (surface it, don't guess).
- **Verify-first crypto.** Every scheme is cross-validated against an external
  oracle, and every GPU/table hit is re-checked by the format's own CPU verifier.
  Never weaken or bypass a verifier to make something pass, and (per the host's
  nevers) never skip, disable or quarantine a test to get green — fix the cause.
- **Keep the three surfaces at parity.** A new capability should reach the engine
  `Options`, the CLI, and (where it makes sense) `xcrackd`/the REST API. A CLI
  subcommand added to `run()`'s dispatch must also appear in `usage()` — there is
  a test (`TestUsageListsEverySubcommand`) that enforces this.
- **Fuzz crashers are regression seeds.** If exploratory fuzzing finds a crasher,
  the minimized input belongs committed under the package's
  `testdata/fuzz/<FuzzName>/`; the deterministic gate then replays it forever.
- **Docs travel with behavior.** A user-facing change updates `docs/CHANGELOG.md`
  (the `[Unreleased]` section) and the relevant doc(s): `docs/USERMANUAL.md`,
  `docs/USAGE.md`, `docs/API.md` (library + REST), and `config/README.md` for new
  config keys. New CLI flags also show in `--help`/`usage()`.

## Resolving a merge conflict

Merge `rom` into the PR head and resolve (the repo uses merge commits; do not
rebase or force-push a shared branch). Regenerate `go.work.sum`/`go.sum` with
`go mod tidy` (via `make tidy`) rather than editing them by hand, then re-run
`make check` before pushing.

## How proactive to be here

The repo owner reviews and merges quickly, and CI is fast (~5–6 min). So:

- Confident, small, in-scope fixes (a real CI failure in code this PR touches, a
  lint/gofmt/vet nit, an obviously-correct review nit): fix, validate, push.
- Anything in the `-tags opencl` GPU tier, an architectural change, or a finding
  whose fix would widen the PR: don't blind-edit — reply on the thread with the
  path you traced and your proposed fix, and put the call to the owner.
- Keep each fix minimal and prove it (reproduce the red, show it green) before
  pushing. One validated push beats three speculative ones.

## Attribution (keep it on every push/PR)

End commit messages with the session's `Co-Authored-By:` and `Claude-Session:`
trailers, and PR bodies with the `🤖 Generated with Claude Code` footer and the
session link, exactly as the session's own instructions specify. Never put a
model identifier anywhere else in the repo.
