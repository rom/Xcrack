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

This repository hosts **three independent Go modules**, layered so each lower
one is reusable on its own:

| Module | Import path | Purpose |
| ------ | ----------- | ------- |
| **Xcrypto** | `github.com/rom/xcrypto` | Standalone **crypto library + cracking engine**: cryptographic primitives, the concrete encryption schemes (ZipCrypto, WinZip AES, OOXML agile/standard), candidate generation, the hashcat-compatible pattern engine, and the concurrent password-search engine. Knows nothing about file formats or recursion — any tool can crack a challenge with it alone. Zero third-party dependencies. |
| **Xfileformats** | `github.com/rom/xfileformats` | Standalone, reusable file-format library: detect a format, parse containers (ZIP, CFB/OLE2), and build an `xcrypto.Challenge`. **Policy-free** — delegates all cryptography to Xcrypto and knows nothing about candidate lists, concurrency, or recursion. |
| **Xcrack** | `github.com/rom/xcrack` | The recovery engine (recursive decomposition, result tree, password promotion, resource budgets) plus the `xcrack` CLI. Imports Xfileformats and Xcrypto. |

```
/
├─ xcrypto/                 module github.com/rom/xcrypto   (crypto + cracking)
│    ├─ prim/               primitives: PBKDF2 · AES-CTR/CBC/ECB · RC4 · Office hash
│    ├─ scheme/…            zipcrypto · winzipaes · ooxml (agile+standard)
│    ├─ candidates/         candidate sources
│    ├─ pattern/            hashcat-compatible masks + rules
│    └─ attack/             concurrent password-search engine
├─ xfileformats/            module github.com/rom/xfileformats  (parse + detect)
│    ├─ formats/zip         ZIP container (per-entry encryption)
│    ├─ formats/ooxml       encrypted MS Office (CFB-wrapped)
│    └─ internal/cfb        OLE2 / compound-file reader
├─ xcrack/                  module github.com/rom/xcrack
│    ├─ pkg/xcrack/         engine: recursion · tree · promotion · budgets · pool
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

Requires Go 1.25+ (a `go.work` ties the three modules together).

```sh
# build everything, run the full test suite (with the race detector)
go build ./xcrypto/... ./xfileformats/... ./xcrack/...
go test -race ./xcrypto/... ./xfileformats/... ./xcrack/...

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

Early but working end to end across all three modules.

**Implemented**
- `xcrypto` (crypto + cracking engine): primitives (PBKDF2, AES-CTR/CBC/ECB,
  RC4, Office agile/standard key derivation); schemes **ZipCrypto**, **WinZip
  AES** (AE-1/AE-2, 128/192/256), **OOXML agile + standard**, and **PDF** (RC4 /
  AESV2 / AESV3, R2-R6, user + owner); candidate sources; a **hashcat-compatible
  pattern engine** (masks `?l?u?d?s?a?b` + ?1-?4, and a practical rule subset);
  and the concurrent, globally-bounded **attack** search engine. Zero
  third-party deps.
- `xfileformats`: detection + registry; **ZIP** container (per-entry
  ZipCrypto/AES); **encrypted MS Office** via a bounded **CFB/OLE2** reader;
  **encrypted PDF** (parse `/Encrypt`+`/ID`, rebuild a decrypted PDF); builds
  `xcrypto.Challenge` and delegates all crypto to Xcrypto. Verified against
  known-answer round-trips and the real `zip` CLI.
- `xcrack` engine: recursive decomposition into a result tree, per-node password
  **and** content, password promotion, resource budgets (depth / total-bytes /
  nodes / entry-size) + ancestor cycle detection, **disk-spill** for large
  intermediates, `recover()` guards on every format call, `context`/budget
  cancellation, and a reusable global pool.
- **Hardening**: fuzz targets on every hostile-input parser (+ the whole
  pipeline) and a decompression-bomb / fan-out / byte-budget / cycle corpus,
  run by `scripts/fuzz.sh` and a GitHub Actions CI workflow. Fuzzing already
  found and fixed a PDF slice-bounds crash and capped the OOXML spin count.
- CLI (`xcrack`, `identify`, `version`): text/JSON/JSONL output, tree extraction
  + `manifest.json`, YAML config, `--pattern` files, concurrent multi-file scan.

**Remaining for the MVP** (see [docs/mvp.md](docs/mvp.md) and
[docs/roadmap.md](docs/roadmap.md))
- Sibling-entry parallelism within one file; `--throttle` / `--max-duration` /
  `--batch-size`; PDF cross-validation against a reference encoder.

**Phase 2 formats** (designed-for): legacy MS Office (`.doc/.xls/.ppt`), ODF,
and the remaining archive unpackers (tar/gzip/bzip2/xz/7z/rar/eml).

## License

MIT (planned). See [`docs/adr/0001-pure-go-no-external-binaries.md`](docs/adr/0001-pure-go-no-external-binaries.md)
and the roadmap for dependency and licensing posture.
