# Xcrack

**Xcrack recovers access to password-protected and encrypted files so their
contents can be inspected.** Its primary role is as an embeddable Go library
inside the **Impex** malicious-content scanner: when Impex meets an encrypted or
password-protected file, Xcrack decrypts it — and recursively unpacks any nested
layers — so the scanner can analyse the real content. It is delivered in three
forms over one engine:

- **Library** (`github.com/rom/xcrack/pkg/xcrack`) — what Impex embeds.
- **CLI** (`xcrack`) — triage, testing, manual recovery.
- **HTTP service** (`xcrackd`) — a backend a thin client (an Impex kiosk or
  DataLock appliance) calls, optionally fronting a separate GPU/OpenCL tier.

👉 **New here? Read [`docs/USAGE.md`](docs/USAGE.md)** for commands, flags, and
many worked examples.

> **Authorized use only.** Xcrack is a defensive / recovery tool, built to run
> against files you own or are explicitly authorized to access — malware-analysis
> pipelines, DFIR, sanctioned engagements, forgotten-password recovery. It
> performs **offline** guessing against a file's own key-derivation function; it
> never attacks remote systems, never executes or renders content, and ships no
> network/online attack modes.

## What it handles

| Family | Formats |
| ------ | ------- |
| **Archives** | ZIP (ZipCrypto, WinZip AES), tar, gzip, bzip2, xz, **7z**, **RAR** — 7z/RAR also **header-encrypted** (`-mhe` / `-hp`) |
| **MS Office** | OOXML (`.docx/.xlsx/.pptx`, agile + standard); legacy (`.doc/.xls/.ppt`: RC4 CryptoAPI, RC4 97-2000, XOR) |
| **Other docs** | PDF (RC4 / AESV2 / AESV3, user + owner); ODF / LibreOffice (AES-256-CBC); **Apple iWork** (Pages/Numbers/Keynote) |
| **Mail / passphrase** | MIME (`.eml`) attachments; **age** (scrypt); **symmetric OpenPGP** (`gpg -c`) |
| **Keys / key stores** | OpenSSH keys; PEM/PKCS#8; JKS; PKCS#12 (`.p12`); PuTTY `.ppk`; SQLCipher |

Every scheme is cross-validated — against known-answer vectors, the real
`zip` / `qpdf` / `7z` / `rar` / `age` / `gpg` CLIs, and byte-for-byte against
gold-standard decrypted legacy-Office documents.

Recovery features: recursive decomposition of nested layers into a result tree
(password **and** content reported per layer), password promotion across layers,
a hashcat-compatible pattern engine (masks + rules) with optional statistical
(Markov) ordering, two-axis globally-bounded concurrency, disk-spill for large
intermediates, resource budgets + bomb defenses, and challenge export/import for
offloading heavy cracking to an external engine.

## Quick start

Requires Go 1.25+ (a `go.work` ties the three modules together).

```sh
make build                    # -> bin/xcrack and bin/xcrackd
make check                    # gofmt check + vet + race tests (what CI runs)

# Decrypt + recursively decompose, writing the tree + manifest.json to ./out:
bin/xcrack -p infected -p Welcome1 -w rockyou.txt -o ./out invoice.zip

# Try it on the bundled samples (every passphrase is "opensesame"):
bin/xcrack -w samples/wordlist.txt samples/zipcrypto.zip samples/secret.pdf

# Detect format / encryption only:
bin/xcrack identify suspicious.bin

# Run the backend service:
bin/xcrackd -addr :8080 -max-procs 16
curl -s --data-binary @invoice.zip 'http://localhost:8080/v1/decrypt?password=infected'
```

Embedding (the Impex pattern) — see `xcrack/examples/impex-embed` and
[`docs/USAGE.md`](docs/USAGE.md#embedding-the-library):

```go
pool := xcrack.NewPool(xcrack.Options{Workers: 4, MaxProcs: 8})
res, _ := pool.Process(ctx, reader, size,
    candidates.Chain(candidates.Explicit(emailPasswords...), candidates.DefaultList()))
res.Root.Walk(func(n *xcrack.Node) { /* scan n.Content ... */ })
```

## Repository layout

Three independent Go modules, layered so each lower one is reusable on its own:

| Module | Import path | Purpose |
| ------ | ----------- | ------- |
| **Xcrypto** | `github.com/rom/xcrypto` | Crypto library + cracking engine: primitives, the concrete encryption schemes, candidate generation, the pattern engine, and the concurrent password search. Core schemes are stdlib-only; extended schemes may use `golang.org/x/crypto`. Knows nothing about file formats or recursion. |
| **Xfileformats** | `github.com/rom/xfileformats` | Policy-free file-format library: detect a format, parse containers (ZIP, CFB/OLE2), build an `xcrypto.Challenge`. Delegates all cryptography to Xcrypto. |
| **Xcrack** | `github.com/rom/xcrack` | The recovery engine (recursive decomposition, result tree, password promotion, budgets, pool), the `xcrack` CLI, and the `xcrackd` HTTP service. |

```
/
├─ Makefile                 build (-> bin/), test, race, vet, fmt, fuzz, …
├─ bin/                     compiled binaries land here (git-ignored)
├─ xcrypto/                 module github.com/rom/xcrypto   (crypto + cracking)
│    ├─ prim/               primitives: PBKDF2 · AES-CTR/CBC/ECB · RC4 · Office hash
│    ├─ scheme/…            zipcrypto · winzipaes · ooxml · pdf · odf · officebinary · age · pgp
│    ├─ candidates/         candidate sources + Markov ordering
│    ├─ pattern/            hashcat-compatible masks + rules
│    └─ attack/             concurrent password-search engine
├─ xfileformats/            module github.com/rom/xfileformats  (parse + detect)
│    ├─ formats/{zip,ooxml,pdf,odf,msoffice,age,pgp,archive}
│    └─ internal/cfb        OLE2 / compound-file reader
├─ xcrack/                  module github.com/rom/xcrack
│    ├─ pkg/xcrack/         engine: recursion · tree · promotion · budgets · pool · metrics
│    ├─ pkg/api/            HTTP service wrapping the engine (Pool)
│    ├─ cmd/xcrack/         CLI
│    └─ cmd/xcrackd/        HTTP service (backend for kiosk / DataLock)
├─ samples/                 encrypted demo files (pw "opensesame") + generate.sh
└─ docs/                    usage, architecture, design, ASR, MVP, threat model, ADRs
```

## Documentation

- **[Usage](docs/USAGE.md)** — commands, flags, config, patterns, library, service — with many examples.
- [Architecture](docs/architecture.md) — system context, containers, components, data flow.
- [Design](docs/design.md) — public APIs, the recursion algorithm, the pattern engine, concurrency, error model.
- [ASR](docs/asr.md) — quality attributes and constraints that shape the architecture.
- [MVP](docs/mvp.md) · [Roadmap](docs/roadmap.md) · [Threat model](docs/threat-model.md) · [ADRs](docs/adr/).

Start with the docs index in [`docs/README.md`](docs/README.md).

## Status

Working end to end across all three modules; **MVP and Phase 2 complete**, with
the service tier and several Phase 3/4 engine features landed:

- **Formats** — the whole table above, each cross-validated (see
  [Roadmap](docs/roadmap.md) for the exact matrix).
- **Service tier** — `xcrackd` HTTP API (`/v1/identify`, `/v1/decrypt`,
  `/v1/metrics`, `/v1/healthz`); `Pool.Metrics()` telemetry; a pluggable live
  candidate provider.
- **Search** — statistical (Markov) candidate ordering; challenge export/import
  so heavy cracking can be offloaded to an external GPU/OpenCL engine (Xcrack
  itself stays pure Go and CPU-only).
- **Hardening** — fuzz targets on every hostile-input parser plus the whole
  pipeline, a decompression-bomb / fan-out / cycle corpus, `recover()` guards on
  every format call, and a GitHub Actions CI workflow (build · vet · gofmt ·
  `-race` · govulncheck · bounded fuzz).

**Staged** (implemented as test fixtures become available): KeePass (needs
in-tree Argon2d), encrypted DMG, ODF AES-GCM, and legacy-Office macro/VBA
auxiliary-stream decryption.

> **Legacy-Office scope.** RC4 CryptoAPI (Office XP/2003) is fully decrypted and
> cross-validated for Word, Excel, and PowerPoint. Office 97/2000 RC4 and XOR
> obfuscation are implemented and unit-tested; XOR *content* reconstruction is
> wired for Excel but not Word (no reference oracle), and only the main document
> streams are decrypted (auxiliary encrypted streams are left as-is).

## License

MIT (planned). See
[`docs/adr/0001-pure-go-no-external-binaries.md`](docs/adr/0001-pure-go-no-external-binaries.md)
and the [roadmap](docs/roadmap.md) for dependency and licensing posture.
