# Xcrack Documentation

This directory contains the usage, architecture, and design documentation for
Xcrack and its standalone formats library, **Xfileformats**.

## Using Xcrack

- **[Usage](USAGE.md)** — how to build (`make`), run the CLI and the `xcrackd`
  service, embed the library, and configure everything, with many examples.
  Start here if you just want to run it.
- **[File formats & variants](FILEFORMATS.md)** — every format Xcrack
  recognizes, which variants of each, how each is detected and verified, and the
  oracle it is cross-validated against.
- **[How Xcrack attacks each format](CRACKING.md)** — per-format KDF/cipher/
  verifier, the attack brought to bear, the verification shortcuts and
  cryptanalysis exploited (or staged), and what the GPU tier accelerates.
- **[FAQ](FAQ.md)** — quick answers on formats, orchestration, methods, KDFs,
  ciphers, shortcuts, candidate ordering, cryptanalysis, config and CLI options.
- **[Terminology](TERMINOLOGY.md)** — the glossary: engine concepts, KDFs,
  ciphers & modes, formats, attacks & shortcuts, and the abbreviations/TLAs that
  recur across these docs.
- **[References](REFERENCES.md)** — the cryptography, cryptanalysis, and
  candidate/attack methods Xcrack uses, with primary references and commentary.
- **[Changelog](CHANGELOG.md)** — notable changes, grouped by the pull request
  that landed them.

## Reading order (design & architecture)

1. **[MVP](mvp.md)** — what the first release does and does not do.
2. **[ASR](asr.md)** — the Architecturally Significant Requirements (quality
   attributes and constraints) that justify the architecture.
3. **[Architecture](architecture.md)** — C4-style views: system context,
   containers (modules), components, and the major data flows.
4. **[Design](design.md)** — concrete public APIs, the recursive decomposition
   algorithm, the candidate/pattern engine, the concurrency model, and the
   error/result model.
5. **[Threat Model](threat-model.md)** — trust boundaries and how Xcrack
   survives hostile input (its normal diet, as a malware pre-processor).
6. **[Roadmap](roadmap.md)** — phased delivery plan beyond the MVP, with a
   detailed [enhancement backlog](roadmap-enhancements.md) (features, cracking
   approaches, formats — tracked with checkboxes).

## Architecture Decision Records

The [`adr/`](adr/) directory records the significant decisions, each with its
context, the options weighed, and the consequences.

| ADR | Decision |
| --- | -------- |
| [0001](adr/0001-pure-go-no-external-binaries.md) | Pure-Go implementation, no external binaries |
| [0002](adr/0002-standalone-xfileformats-library.md) | Split formats into the standalone **Xfileformats** library |
| [0003](adr/0003-recursive-decomposition-model.md) | Recursive decomposition with a result tree |
| [0004](adr/0004-hostile-input-safety-budgets.md) | Hostile-input safety and resource budgets |
| [0005](adr/0005-hashcat-compatible-pattern-engine.md) | hashcat-compatible mask/rule pattern engine |
| [0006](adr/0006-concurrency-model.md) | Two-axis concurrency model with a shared pool |
| [0007](adr/0007-documents-as-leaves.md) | Documents treated as leaves; opt-in explosion |
| [0008](adr/0008-config-and-output.md) | Configuration precedence and output handling |
| [0009](adr/0009-extract-xcrypto.md) | Extract all crypto + cracking into the standalone Xcrypto module |

## Terminology

The glossary has moved to **[TERMINOLOGY.md](TERMINOLOGY.md)** and been extended
well beyond the core engine terms to cover KDFs, ciphers & modes, file formats &
containers, attacks & cryptanalysis shortcuts, acceleration, and the
abbreviations/TLAs used throughout the docs. The essentials:

- **Candidate** — a single password string to test against a file.
- **Challenge** — the crypto material (salt, verifier, KDF parameters) a format
  exposes so candidates can be tested without re-reading the whole file.
- **Encryption layer / Container layer** — a file that must be decrypted / a file
  that holds other files and must be unpacked.
- **Node / Leaf** — one position in the decomposition tree / a node that is
  neither encrypted nor a container (real content handed back to the caller).
- **Password promotion** — trying a password that unlocked an outer layer first
  on inner layers, since nested packaging reuses passwords.
- **Budget / limits** — the caps (depth, bytes, node count, ratio, time) that
  bound work and defeat decompression bombs.

→ **Full glossary: [TERMINOLOGY.md](TERMINOLOGY.md).**
