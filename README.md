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

## Status

Pre-implementation. The documentation set is being finalised before the two
modules are scaffolded and the MVP formats are implemented.

## License

MIT (planned). See [`docs/adr/0001-pure-go-no-external-binaries.md`](docs/adr/0001-pure-go-no-external-binaries.md)
and the roadmap for dependency and licensing posture.
