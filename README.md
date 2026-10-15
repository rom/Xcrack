# Xcrack

Xcrack recovers access to password-protected and encrypted files so their
contents can be inspected. Its primary role is as an **embeddable Go library**
inside the **Impex** malicious-content scanner: when Impex encounters an
encrypted or password-protected file, Xcrack decrypts it (and recursively
unpacks any nested layers) so the scanner can analyse the real content.

A standalone **CLI** is also provided for triage, testing, and manual recovery.

> **Authorized use only.** Xcrack is a defensive / recovery tool. It is built to
> be run against files you own or are explicitly authorized to access —
> malware analysis pipelines, DFIR, sanctioned engagements, and recovery of your
> own forgotten passwords. It performs **offline** attacks against a file's own
> key-derivation function; it does not attack remote systems and ships no
> network/online attack modes.

## Repository layout

This repository hosts **two independent Go modules**:

| Module | Import path | Purpose |
| ------ | ----------- | ------- |
| **Xfileformats** | `github.com/rom/xfileformats` | Standalone, reusable file-format library: detect a format, probe its encryption, verify/decrypt with a given password, and unpack container formats. **Policy-free** — it knows nothing about candidate lists, concurrency, or recursion. Reusable by any tool. |
| **Xcrack** | `github.com/rom/xcrack` | The recovery engine (candidate generation, pattern/rule engine, concurrency pools, recursive decomposition, resource budgets, result tree) plus the `xcrack` CLI. Imports Xfileformats. |

```
/
├─ xfileformats/            module github.com/rom/xfileformats
│    detect · probe · verify · decrypt · unpack  (reusable, policy-free)
├─ xcrack/                  module github.com/rom/xcrack
│    ├─ pkg/xcrack/         engine: candidates · patterns · pools · recursion
│    └─ cmd/xcrack/         CLI
└─ docs/                    architecture, design, ASR, MVP, threat model, ADRs
```

## Documentation

Start with [`docs/README.md`](docs/README.md). Key documents:

- [Architecture](docs/architecture.md) — system context, containers, components, data flow.
- [Design](docs/design.md) — public APIs, the recursion algorithm, the pattern engine, concurrency, error model.
- [Architecturally Significant Requirements](docs/asr.md) — quality attributes and constraints that shape the architecture.
- [MVP](docs/mvp.md) — first-release scope and acceptance criteria.
- [Threat Model](docs/threat-model.md) — hostile-input handling and trust boundaries.
- [Roadmap](docs/roadmap.md) — phased delivery plan.
- [ADRs](docs/adr/) — the record of the major architecture decisions.

## Building & running

Requires Go 1.25+ (a `go.work` ties the two modules together).

```sh
# build everything, run the full test suite (with the race detector)
go build ./xfileformats/... ./xcrack/...
go test -race ./xfileformats/... ./xcrack/...

# build the CLI
go build -o xcrack ./xcrack/cmd/xcrack

# decrypt + recursively decompose an archive, writing the tree to ./out
./xcrack -p infected -p Welcome1 -w rockyou.txt -o ./out invoice.zip

# detect format / encryption only
./xcrack identify suspicious.bin
```

Embedding (the Impex pattern) — see `xcrack/examples/impex-embed`:

```go
pool := xcrack.NewPool(xcrack.Options{Workers: 4, MaxProcs: 8})
res, _ := pool.Process(ctx, reader, size,
    candidates.Chain(candidates.Explicit(emailPasswords...), candidates.DefaultList()))
res.Root.Walk(func(n *xcrack.Node) { /* scan n.Content ... */ })
```

## Status

Early implementation. Documentation set complete; the first vertical slice is
working end to end.

**Implemented**
- `xfileformats`: format/registry/challenge core; **ZIP** container with
  **ZipCrypto** (traditional PKWARE) and **WinZip AES** (AE-1/AE-2, 128/192/256)
  decryption — verified against known-answer round-trips and the real `zip` CLI.
- `xcrack` engine: recursive decomposition into a result tree, per-node password
  **and** content, password promotion, resource budgets (depth / total-bytes /
  nodes / entry-size) and ancestor-based cycle detection, `recover()` guards on
  every format call, a concurrent candidate search bounded by a reusable global
  `Pool`, and `context`/budget cancellation.
- Candidate sources: explicit, wordlist (+gzip, +stdin), built-in default list,
  de-duplicating chain, in-memory programmatic injection.
- CLI (`xcrack`, `identify`, `version`) with text/JSON/JSONL output, tree
  extraction + `manifest.json`, YAML config, and concurrent multi-file scanning.

**Remaining for the MVP** (see [docs/mvp.md](docs/mvp.md) and
[docs/roadmap.md](docs/roadmap.md))
- Formats: OOXML MS Office (agile + standard) and PDF (RC4 / AESV2 / AESV3).
- The hashcat-compatible mask/rule pattern engine (`--pattern`).
- Disk-spill for large intermediates; sibling-entry parallelism within one file;
  `--throttle` / `--max-duration` / `--batch-size`; fuzz + bomb corpora in CI.

## License

MIT (planned). See [`docs/adr/0001-pure-go-no-external-binaries.md`](docs/adr/0001-pure-go-no-external-binaries.md)
and the roadmap for dependency and licensing posture.
