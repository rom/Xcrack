# Xcrack — Usage

Xcrack recovers access to password-protected and encrypted files so their
contents can be inspected (its primary job is feeding decrypted bytes to the
**Impex** malicious-content scanner). It comes in **three forms over one
engine**:

1. **CLI** — `xcrack` / `xcrackd` — triage, testing, manual recovery, and a
   backend service.
2. **Embeddable library** — `github.com/rom/xcrack/pkg/xcrack` — what Impex
   links.
3. **HTTP service** — `xcrackd` — a backend a thin client (an Impex kiosk or
   DataLock appliance) calls.

> **Authorized use only.** Xcrack performs **offline** guessing against a
> file's own key-derivation function. Run it only against files you own or are
> explicitly authorized to access. It never attacks remote systems, never
> executes or renders file content, and ships no online/network attack modes.

## Contents

- [Building](#building)
- [CLI](#cli)
  - [Sources](#sources)
  - [Candidate passwords](#candidate-passwords)
  - [Output](#output)
  - [Concurrency](#concurrency)
  - [Recursion & documents](#recursion--documents)
  - [Resource limits](#resource-limits)
  - [Config file](#config-file)
  - [Environment variables](#environment-variables)
  - [Exit codes](#exit-codes)
  - [Worked examples by format](#worked-examples-by-format)
  - [`identify`](#identify)
- [Pattern engine (masks & rules)](#pattern-engine-masks--rules)
- [Embedding the library](#embedding-the-library)
- [HTTP service (`xcrackd`)](#http-service-xcrackd)
- [Challenge export / GPU offload](#challenge-export--gpu-offload)
- [Supported formats](#supported-formats)

---

## Building

Requires Go 1.25+. A `go.work` ties the three modules together.

```sh
make build        # -> bin/xcrack and bin/xcrackd
make cli          # just the CLI
make server       # just the HTTP service
make test         # run the test suite
make race         # tests under the race detector
make check        # gofmt check + vet + race (what CI runs)
make fuzz DUR=30s # run every fuzz target for 30s each
make install      # go install both commands into GOBIN
make help         # list all targets
```

Or directly:

```sh
go build -o bin/xcrack  ./xcrack/cmd/xcrack
go build -o bin/xcrackd ./xcrack/cmd/xcrackd
```

---

## CLI

```
xcrack [flags] [sources...]      decrypt and recursively decompose sources
xcrack identify [sources...]     detect format & encryption only (no cracking)
xcrack version
xcrack help
```

Sources may be given positionally or with `-s`. The exit code reflects the
outcome (see [Exit codes](#exit-codes)).

### Sources

| Flag | Meaning |
| ---- | ------- |
| `-s`, `--source PATH` | a file, directory (recursed), or glob — repeatable |
| *(positional)* | same as `--source` |

```sh
xcrack secret.zip                      # one file
xcrack -s a.zip -s b.docx              # several files
xcrack '/samples/*.7z'                 # a glob (quote it so the shell doesn't expand)
xcrack /inbox/                         # every file under a directory, recursively
```

### Candidate passwords

Candidates are tried in this order: explicit passwords, the built-in default
list, then each wordlist (expanded by any mangling rules), then mask keyspaces.
A recovered password is **promoted** to the front for inner layers, so a nested
archive that reuses a password is unlocked almost for free.

| Flag | Meaning |
| ---- | ------- |
| `-p`, `--password STR` | an explicit candidate — repeatable |
| `-w`, `--wordlist FILE` | a wordlist; `-` reads stdin; `.gz` auto-detected — repeatable |
| `--pattern FILE` | a mask/rule pattern file — repeatable (see [Pattern engine](#pattern-engine-masks--rules)) |
| `--no-default-list` | disable the built-in common-password list |

```sh
# A couple of guesses plus the built-in list:
xcrack -p infected -p Welcome1 invoice.zip

# A wordlist (gzip is fine), default list disabled:
xcrack -w rockyou.txt.gz --no-default-list suspicious.doc

# Pipe candidates in on stdin:
generate-candidates | xcrack -w - payload.7z

# Only try the built-in list (no flags needed — it's on by default):
xcrack quote.pdf
```

### Output

| Flag | Meaning |
| ---- | ------- |
| `--format text\|json\|jsonl` | result rendering (default `text`) |
| `-o`, `--out DIR` | write the decrypted tree under `DIR/<name>.extracted/` + a `manifest.json` |
| `--results-file FILE` | append a JSON manifest per input to `FILE` |
| `--log-level LEVEL` | `debug\|info\|warn\|error` (reserved; structured logging is phase 2) |

```sh
# Human-readable tree:
xcrack -p hunter2 archive.zip

# Machine-readable, one JSON document (tree + recovered passwords + stats):
xcrack --format json -p hunter2 archive.zip

# One JSON object per node (stream-friendly):
xcrack --format jsonl -p hunter2 archive.zip

# Extract every decrypted/plain leaf to disk + manifest.json:
xcrack -p hunter2 -o ./out archive.zip
#   -> ./out/archive.zip.extracted/...        (mirrors the tree)
#   -> ./out/archive.zip.extracted/manifest.json
```

Recovered passwords appear in the result and the manifest; they are **never**
written to logs.

### Concurrency

Two independent axes, globally bounded so a batch never exceeds the host's CPU
envelope (see [ADR-0006](adr/0006-concurrency-model.md)).

| Flag | Meaning |
| ---- | ------- |
| `--workers N` | candidate-test goroutines **within** one file (0 = NumCPU) |
| `--file-jobs N` | files / sibling entries processed **concurrently** (0 = NumCPU) |
| `--max-procs N` | global ceiling on live candidate testers across everything (0 = NumCPU) |
| `--batch-size N` | candidates per worker hand-off (0 = auto); amortizes channel overhead |
| `--throttle PCT` | approximate CPU duty cycle `1..99` (0 = no throttle) |
| `--timeout D` | per-file time budget, e.g. `30s`, `5m` |
| `--max-duration D` | whole-run deadline |

```sh
# Scan a directory, 8 files at a time, 4 testers each, capped at 16 total:
xcrack --file-jobs 8 --workers 4 --max-procs 16 -w rockyou.txt /inbox/

# Be a background citizen: ~30% CPU, give up on any one file after 20s:
xcrack --throttle 30 --timeout 20s -w rockyou.txt /inbox/
```

### Recursion & documents

| Flag | Meaning |
| ---- | ------- |
| `--recurse` / `--no-recurse` | decompose nested containers (default: on) |
| `--explode-documents` | also decompose documents (OOXML/PDF/…) into internal parts |

```sh
# Encrypted ZIP -> encrypted .docx -> inner ZIP -> text, all in one pass:
xcrack -p infected nested.zip

# Treat documents as leaves (don't explode .docx into its parts):
xcrack --no-recurse report.docx     # (or leave recurse on; documents are leaves by default)

# Opt into document explosion:
xcrack --explode-documents -p hunter2 report.docx
```

### Resource limits

Bomb defenses have safe floors; you can tighten them but not disable them.

| Flag | Meaning |
| ---- | ------- |
| `--max-depth N` | max nesting depth (0 = default 32) |
| `--max-total-bytes N` | cumulative decompressed-byte budget |
| `--max-nodes N` | max extracted entries |
| `--max-entry-size N` | max single-entry size |
| `--max-candidates N` | max candidates tested per encrypted node (0 = unlimited) |

```sh
xcrack --max-depth 8 --max-total-bytes 1073741824 --max-candidates 100000 -w big.txt bomb.zip
```

### Config file

`-c/--config FILE` loads YAML. Precedence is **flags > environment > config >
defaults**. A full example:

```yaml
# xcrack.yaml
concurrency:
  workers: 4
  file_jobs: 8
  max_procs: 16
  batch_size: 64
  throttle: 0            # 1..99 to cap CPU; 0 = off

limits:
  max_depth: 32
  max_total_bytes: 1073741824
  max_nodes: 100000
  max_entry_size: 536870912
  max_candidates: 0      # 0 = unlimited

recursion:
  recurse: true
  explode_documents: false

search:
  promote_passwords: true

candidates:
  passwords: [infected, Welcome1]
  wordlists: [rockyou.txt, corp-words.txt.gz]
  use_default_list: true

patterns:
  masks:
    - "?u?l?l?l?d?d?d?d"
  rules:
    - "c $1 $2 $3"       # capitalize, append "123"
  custom_charsets:
    "1": "abcdef0123456789"

output:
  format: json
  results_file: results.ndjson

budget:
  per_file: 30s
  total: 10m
```

```sh
xcrack -c xcrack.yaml /inbox/
xcrack -c xcrack.yaml --workers 2 /inbox/     # flag overrides the config
```

### Environment variables

Override the config but not explicit flags:

| Variable | Effect |
| -------- | ------ |
| `XCRACK_WORKERS` | `--workers` |
| `XCRACK_FILE_JOBS` | `--file-jobs` |
| `XCRACK_MAX_PROCS` | `--max-procs` |
| `XCRACK_THROTTLE` | `--throttle` |
| `XCRACK_FORMAT_STR` | `--format` |

```sh
XCRACK_MAX_PROCS=8 XCRACK_FORMAT_STR=json xcrack -w rockyou.txt /inbox/
```

### Exit codes

| Code | Meaning |
| ---- | ------- |
| `0` | at least one node decrypted, or nothing needed cracking |
| `1` | something stayed locked and nothing was decrypted |
| `2` | a usage or processing error occurred (details on stderr) |

### Worked examples by format

```sh
# --- ZIP (ZipCrypto or WinZip AES) ---
xcrack -p infected -w rockyou.txt invoice.zip

# --- Encrypted Office (OOXML: .docx/.xlsx/.pptx) ---
xcrack -p 'S3cret!' quarterly.xlsx

# --- Encrypted PDF (user OR owner password) ---
xcrack -w rockyou.txt statement.pdf

# --- LibreOffice / OpenOffice (ODF: .odt/.ods/.odp) ---
xcrack -p hunter2 notes.odt

# --- Legacy MS Office (.doc/.xls/.ppt: RC4 CryptoAPI / RC4 97-2000 / XOR) ---
xcrack -p myhovercraftisfullofeels old-memo.doc

# --- age (passphrase) ---
xcrack -p 'correct horse battery staple' secrets.age

# --- Symmetric OpenPGP (gpg -c) ---
xcrack -w rockyou.txt message.gpg

# --- 7z / RAR, content- OR header-encrypted (-mhe / -hp) ---
xcrack -p Hunter2 archive.7z
xcrack -p Hunter2 archive.rar

# --- Nested: encrypted 7z containing an encrypted .docx (password reuse) ---
xcrack -p SharedPass bundle.7z        # promotion unlocks the inner .docx for free

# --- A whole quarantine directory, JSON out, bounded ---
xcrack --format json --file-jobs 8 --timeout 30s -w rockyou.txt -o ./triaged /quarantine/
```

### `identify`

Detect format and encryption **without** attempting any password:

```sh
xcrack identify suspicious.bin mystery.dat
# suspicious.bin: format=ooxml container=false encrypted=true explodable=false
# mystery.dat: format=zip container=true encrypted=false explodable=false
```

---

## Pattern engine (masks & rules)

Hashcat-compatible masks and a practical rule subset, supplied via `--pattern
FILE` (repeatable) or the config's `patterns:` block.

**Mask placeholders:** `?l` lower, `?u` upper, `?d` digit, `?s` symbol, `?a`
all printable, `?b` all bytes, and `?1`–`?4` custom charsets.

**Pattern file DSL** (`#` comments; a bare line is treated as a mask):

```
# patterns.txt
charset1: abcdef0123456789       # defines ?1
mask: ?u?l?l?l?d?d?d?d           # Abcd1234-style
mask: ?1?1?1?1?1?1               # six hex chars
rule: c                          # capitalize each wordlist entry
rule: $2 $0 $1 $9                # append "2019"
```

```sh
# Masks as standalone keyspaces:
xcrack --pattern patterns.txt locked.zip

# Rules mangle each wordlist entry (wordlist x rules):
xcrack -w names.txt --pattern patterns.txt locked.zip
```

Masks run as their own keyspaces (appended after wordlists); rules expand each
wordlist entry. Keep mask keyspaces small — this is CPU-only guessing, not GPU.

---

## Embedding the library

The engine is library-first; the CLI is a thin wrapper. Construct a `Pool`
once (e.g. at service start) and feed many files through it concurrently — the
global semaphore bounds total CPU regardless of how many are in flight.

```go
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

func main() {
	pool := xcrack.NewPool(xcrack.Options{
		Workers:         4,
		MaxProcs:        16,
		FileConcurrency: 8,
	})
	defer pool.Close()

	data, _ := os.ReadFile("invoice.zip")

	// Per-scan candidates: a few known passwords, then the built-in list.
	src := candidates.Chain(
		candidates.Explicit("infected", "Welcome1"),
		candidates.DefaultList(),
	)

	res, err := pool.Process(context.Background(), bytes.NewReader(data), int64(len(data)), src)
	if err != nil {
		panic(err)
	}
	defer res.Close() // release any disk-spilled intermediates

	// Walk the tree and scan every recovered leaf.
	res.Root.Walk(func(n *xcrack.Node) {
		if n.Content != nil {
			rc, _ := n.Content.Open()
			defer rc.Close()
			// scan rc ... (this is where Impex runs its detectors)
		}
		if n.WasEncrypted {
			fmt.Printf("%s unlocked with %q\n", n.Path, n.Password)
		}
	})

	fmt.Println("recovered:", res.Passwords())
}
```

Useful pieces of the public API:

- **`xcrack.Options`** — every CLI flag is a field here (full CLI/library parity).
- **`pool.Process(ctx, io.ReaderAt, size, CandidateSource)`** — returns a `*Result`.
- **`Result.Root`** — a `*Node` tree; each node carries `Format`, `WasEncrypted`,
  `Password`, `Status`, and `Content` (a `ContentRef` you `Open()` on demand).
- **`Result.Passwords()`** — every distinct recovered password.
- **`xcrack.BuildReport(res)`** — the stable JSON projection (the CLI and the
  HTTP API both use it).
- **`Options.CandidateProvider`** — plug in a live per-scan source once at Pool
  construction instead of passing one to every call:

  ```go
  pool := xcrack.NewPool(xcrack.Options{
      CandidateProvider: xcrack.CandidateProviderFunc(func(ctx context.Context) xcrack.CandidateSource {
          return candidates.Explicit(perScanPasswordsFrom(ctx)...)
      }),
  })
  ```

- **`pool.Metrics()`** — aggregate counters (files, candidates tried, bytes,
  nodes by status, durations) for telemetry; carries no secrets.

Candidate sources live in `github.com/rom/xcrypto/candidates`: `Explicit`,
`Bytes`, `File` (gzip-aware), `Stdin`, `DefaultList`, `Chain`, and `ByScore`
(+ a `Markov` model) to order a wordlist's head by likelihood.

---

## HTTP service (`xcrackd`)

Run the engine on a hardened backend so a thin client (an Impex **kiosk** or
**DataLock** appliance) can POST a file and get back the decrypted tree. The
cryptanalysis stays offline — the service only attacks the submitted file's own
KDF.

```sh
xcrackd -addr :8080 -max-procs 16
# or: make run-server ADDR=:8080
```

| Flag | Default | Meaning |
| ---- | ------- | ------- |
| `-addr` | `:8080` | listen address |
| `-workers` / `-max-procs` / `-file-jobs` | NumCPU | pool concurrency |
| `-max-body` | 256 MiB | max request body |
| `-request-timeout` | 120s | per-request processing deadline |
| `-allow-default-list` | off | permit `?defaults=true` to use the embedded wordlist |
| `-read-timeout` / `-write-timeout` | 30s / 150s | HTTP timeouts |
| `-shutdown-grace` | 20s | graceful-shutdown window |

**Endpoints:**

| Method & path | Purpose |
| ------------- | ------- |
| `GET /v1/healthz` | liveness |
| `GET /v1/metrics` | aggregate counters (JSON, no secrets) |
| `POST /v1/identify` | detect format/encryption only (no cracking) |
| `POST /v1/decrypt` | decrypt + recursively decompose |

Both POST routes take the **raw file as the request body**; candidates come
from repeated `?password=` query values and an opt-in `?defaults=true`.

```sh
# Detect only:
curl -s --data-binary @suspicious.bin http://localhost:8080/v1/identify

# Decrypt with a couple of candidate passwords:
curl -s --data-binary @invoice.zip \
  'http://localhost:8080/v1/decrypt?password=infected&password=Welcome1'

# Use the server's embedded list too (only if started with -allow-default-list):
curl -s --data-binary @invoice.zip 'http://localhost:8080/v1/decrypt?defaults=true'

# Telemetry:
curl -s http://localhost:8080/v1/metrics
```

The response is the same JSON tree the library/CLI produce:

```json
{
  "root": {
    "path": "", "format": "zip", "status": "plain",
    "children": [
      { "path": "secret.txt", "format": "", "status": "decrypted",
        "encrypted": true, "password": "infected", "size": 1234,
        "sha256": "…" }
    ]
  },
  "recovered_passwords": ["infected"],
  "stats": { "candidates_tried": 2, "bytes_extracted": 1234, "elapsed_ms": 3 }
}
```

> **Security:** `xcrackd` ships **no authentication or TLS** by design. Put it
> behind a reverse proxy / service mesh that provides authn/z and transport
> security, and never expose it directly to an untrusted network. Responses
> carry recovered passwords and content digests — treat them as sensitive.

---

## Challenge export / GPU offload

Xcrack guesses on CPU and never ships GPU code. For a huge keyspace you can
export a probed **challenge** as portable JSON, crack it in an external engine
(e.g. a GPU/OpenCL tier), and re-import the recovered password to resume
decryption. The library's `xcrypto` package provides:

```go
data, _ := xcrypto.MarshalChallenge(ch, "invoice.doc!/WordDocument") // -> JSON envelope
ch2, source, _ := xcrypto.UnmarshalChallenge(data)                   // round-trips

// The external engine returns the password; import it to continue:
out, _ := xcrypto.MarshalRecoveredPassword(source, "Password1234_")
rec, _ := xcrypto.UnmarshalRecoveredPassword(out)
_ = rec.Password
```

The envelope's `scheme` field is the stable discriminator an external bridge
keys on; byte fields are hex-encoded.

---

## Supported formats

| Family | Formats | Notes |
| ------ | ------- | ----- |
| Archives | ZIP (ZipCrypto, WinZip AES), tar, gzip, bzip2, xz, **7z**, **RAR** | 7z/RAR also **header-encrypted** (`-mhe` / `-hp`) |
| MS Office | OOXML (`.docx/.xlsx/.pptx`, agile + standard), legacy (`.doc/.xls/.ppt`: RC4 CryptoAPI / RC4 97-2000 / XOR) | legacy XOR body reconstruction: Excel only |
| Other docs | PDF (RC4 / AESV2 / AESV3, user + owner), ODF (AES-256-CBC) | |
| Mail / passphrase | MIME (`.eml`) attachments, **age** (scrypt), **symmetric OpenPGP** (`gpg -c`) | |

Not yet implemented (staged, pending test fixtures): KeePass, SQLCipher, Apple
iWork, encrypted DMG, ODF AES-GCM, and legacy-Office macro/VBA auxiliary-stream
decryption. Out of scope: GPU cracking in-tree, any online/network attack, and
public-key PDF (needs a private key, not a password). See the
[roadmap](roadmap.md).
