# Xcrack User Manual

A task-oriented guide to running Xcrack. For the exhaustive flag reference see
[`USAGE.md`](USAGE.md); for how each format is attacked see
[`CRACKING.md`](CRACKING.md); for speed see [`PERFORMANCE.md`](PERFORMANCE.md);
for the vocabulary see [`TERMINOLOGY.md`](TERMINOLOGY.md); for quick answers see
[`FAQ.md`](FAQ.md).

> **Authorized use only.** Xcrack is a recovery / defensive tool. Use it only on
> files you own or are explicitly authorized to access.

## Contents

1. [Introduction](#1-introduction)
2. [How to use the tool](#2-how-to-use-the-tool)
3. [GPU acceleration](#3-gpu-acceleration)
4. [Distributed environments](#4-distributed-environments)
5. [Advanced usage](#5-advanced-usage)
6. [Logging and the audit trail](#6-logging-and-the-audit-trail)
7. [Debugging and troubleshooting](#7-debugging-and-troubleshooting)

---

## 1. Introduction

Xcrack recovers passwords for, and decrypts, password-protected files. It is
three things in one tree:

- **`xcrack`** — the command-line tool: identify, triage, and crack files, and
  run the non-brute-force recoveries (key attacks, known-plaintext, header
  decode).
- **`xcrackd`** — an HTTP service and the host for the opt-in GPU tier; also a
  cracking worker for a distributed fleet.
- **a Go library** (`xcrypto`, `xfileformats`, `pkg/xcrack`) — embed the engine
  in your own program.

**What makes it different.** Xcrack reads a file's *content*, not its extension,
and **recursively decomposes** nested packaging — an encrypted PDF inside an
encrypted ZIP inside a `.tar.zst` is found and cracked automatically, with no
manual `*2john` step. It never breaks sound cryptography: it recovers the
*password* (by testing candidates against the format's own verifier) or, for a
few legacy schemes with a real weakness, the *key* directly. Every scheme is
cross-validated against an independent oracle, and a decrypted result is always
authoritatively verified — there are no false positives.

**What it can and cannot do.** A weak, reused, or list-derivable password behind
any supported format is recoverable; a long, random password behind a strong
cipher and an expensive KDF is not (that is the design). See
[`FAQ.md`](FAQ.md#cracking-limitations).

**Install / build.**

```sh
make build          # -> bin/xcrack and bin/xcrackd
# or:
go build -o bin/xcrack  ./xcrack/cmd/xcrack
go build -o bin/xcrackd ./xcrack/cmd/xcrackd
```

The default build is pure-Go and cgo-free; it needs no system libraries.

---

## 2. How to use the tool

### Identify first

```sh
xcrack identify FILE          # what format/scheme is this, and is it encrypted?
```

### Try the free wins before a search

Many files do not need brute force. Xcrack tries these automatically, and you
can invoke the key-level ones directly:

```sh
xcrack office-keyattack legacy.doc     # Office 97/2000: sweep the 40-bit key
xcrack pdf-keyattack scanned.pdf       # PDF V1/R2: sweep the 40-bit file key
xcrack access-recover database.mdb     # Access Jet: read the password from the header
xcrack vba-recover macros.xls          # VBA project password
xcrack kp --plain known.bin --cipher entry.bin --zip archive.zip --zip-out ./out
                                       # ZipCrypto known-plaintext; one recovery unlocks all entries
```

### Run a password search

```sh
xcrack -w rockyou.txt secret.zip                    # wordlist
xcrack -w rockyou.txt --pattern rules/best64.rule secret.zip   # wordlist + rules
xcrack -p 'Hunter2' secret.zip                      # a single explicit password
xcrack --hcmask '?u?l?l?l?l?d?d' secret.zip         # mask / brute force
xcrack -w words.txt --hybrid-append '?d?d?d' secret.zip        # hybrid
```

Write the decrypted tree out with `-o`:

```sh
xcrack -w rockyou.txt -o ./out secret.zip           # decrypts and extracts under ./out/
```

### Crack many files at once

```sh
xcrack -w rockyou.txt -o ./out samples/*            # concurrent; output in argument order
xcrack --cost-queue -w rockyou.txt -o ./out *.*     # attack the weakest/fastest schemes first
xcrack --time-limit 5m -w rockyou.txt *.*           # never let one hard file block the batch
```

### Remember what you find

```sh
xcrack --remember -w rockyou.txt -o ./out *.*       # persist recovered passwords (potfile)
xcrack --remember --loopback -w rockyou.txt *.*     # also re-mangle found passwords (Summer2023 -> Summer2024!)
xcrack --reuse-output -o ./out *.*                  # skip re-extracting unchanged sources (near-instant repeat)
```

### Force a format with no magic bytes

```sh
xcrack --as sqlcipher -w rockyou.txt notes.db
xcrack --as vbaproject -w rockyou.txt macros.xls
```

### Offload to hashcat / John instead of cracking in-engine

```sh
xcrack hashline target.pdf > hashes.txt             # emit $pdf$/$office$/$zip2$/$dmg$
xcrack export-challenge target.kdbx > challenge.json
# ... solve on a GPU rig, then re-import:
xcrack --resume-from solved.json -o ./out target.kdbx
```

`xcrack --help` lists every flag and subcommand; [`USAGE.md`](USAGE.md) has the
full reference and many worked examples.

---

## 3. GPU acceleration

The GPU tier is an **opt-in** exception to the pure-Go default (ADR 0001): it
exists only in a `-tags opencl` build, and a default build is CPU-only. There are
two ways to use a GPU, and a way to run the CPU and GPU **at the same time**.

### A. The standalone 40-bit key-search sweeps (`xcrack …-keyattack --gpu`)

These crack legacy 40-bit RC4 Office/PDF files by sweeping the key space, and
offload that sweep to an OpenCL device directly. Build with `-tags opencl`:

```sh
go build -tags opencl -o bin/xcrack ./xcrack/cmd/xcrack
bin/xcrack office-keyattack --gpu legacy.doc
bin/xcrack pdf-keyattack   --gpu scanned.pdf
```

Without a device (or in a default build) `--gpu` logs why and falls back to the
CPU sweep. A hit is always re-checked on the CPU.

### B. The live crack loop on a GPU (`xcrackd --gpu`, or `xcrack --gpu`)

Both the server and the CLI can offload the heavy per-candidate KDF of a normal
password search to the GPU. Build and self-test the server first:

```sh
go build -tags opencl -o bin/xcrackd-gpu ./xcrack/cmd/xcrackd
bin/xcrackd-gpu -gpu-selftest           # prove the kernels match the CPU reference, then exit
bin/xcrackd-gpu -gpu -addr :8080        # hardware-gated; falls back to CPU if no device
```

Then point the CLI at it (see [Distributed environments](#4-distributed-environments)),
or POST files to the HTTP endpoint. The CLI can also drive a local device itself:

```sh
go build -tags opencl -o bin/xcrack ./xcrack/cmd/xcrack
bin/xcrack --gpu -s vault.dmg -w rockyou.txt    # offload the live sweep to the GPU
```

`--gpu` is hardware-gated on both: with no device (or in a default build) it logs
why and runs the unchanged CPU search.

### C. Dual CPU+GPU pipeline (`--dual-pipeline`)

By default the GPU sweeps the keyspace while the CPU waits. `--dual-pipeline`
(on `xcrack` or `xcrackd`, with `--gpu`) instead runs **both at once over one
shared candidate stream**: each candidate is handed to exactly one lane (no
double work), and the **first lane to find the password cancels the other**, so
both move on to the next file. The CPU clears the cheap, likely guesses at the
front of the stream without waiting for a device batch, while the GPU grinds
through the bulk — the two lanes cover the keyspace together.

```sh
bin/xcrack  --gpu --dual-pipeline -s vault.dmg -w rockyou.txt
bin/xcrackd-gpu -gpu -dual-pipeline -addr :8080
```

It is a **speed** change, never a result change: the device's hits are always
re-checked on the CPU, so it can't cause a false positive, and if the device
can't serve a target mid-run the pipeline re-verifies the pending batch on the
CPU and finishes on the CPU lane — no candidate is skipped. It is inert without
an active `--gpu` tier.

**What the GPU accelerates:** PBKDF2-HMAC-SHA1/256/512 (WinZip-AES, DMG, ODF,
RAR5, SQLCipher-v4-class), the Office 2010+ agile/standard iterated-hash spin,
the Office 97/2000 and PDF 40-bit key searches, and the VBA salted-SHA-1 batch.
It auto-tunes the batch size and splits across multiple devices.
`XCRACK_GPU_DEVICE=<name-or-vendor-substring>` forces a specific device.

**What stays on the CPU** (memory-hard or GPU-hostile): Argon2 (KeePass KDBX4,
PuTTY v3), scrypt (age, Ethereum, PBES2), bcrypt (OpenSSH), and SQLCipher
(ambiguous v3/v4 profile). See [`CRACKING.md`](CRACKING.md) §4.

**No GPU of your own?** Use path A/B on a rented box, or offload to hashcat/John
with `hashline` / `export-challenge` (section 2).

---

## 4. Distributed environments

Two models, which compose.

### Manual sharding (no servers)

Each machine runs the same inputs over a disjoint stride of the keyspace:

```sh
xcrack --shard 0/4 -w huge.txt big.zip      # machine 0
xcrack --shard 1/4 -w huge.txt big.zip      # machine 1   (… 2/4, 3/4 on the others)
```

The standalone key attacks shard the same way:

```sh
xcrack office-keyattack --shard 0/8 legacy.doc    # 8-way split of the 2^40 sweep
```

### A fleet of `xcrackd` workers

Run `xcrackd` on each worker (optionally GPU-accelerated), then drive them from
one CLI:

```sh
# on each worker:
xcrackd -addr :8080 -max-procs 16            # add -gpu on GPU boxes (needs -tags opencl)

# from the controller — collective: all workers share one keyspace:
xcrack --server http://w1:8080 --server http://w2:8080 \
       --cluster-mode collective --cluster-session fleet.session \
       -w rockyou.txt -o ./out big.7z

# partition: groups of workers take different files in a batch:
xcrack --server http://a:8080@g1 --server http://b:8080@g1 \
       --server http://c:8080@g2 --server http://d:8080@g2 \
       --cluster-mode partition -w rockyou.txt *.docx
```

Key flags: `--server URL[@GROUP]` (repeatable), `--cluster-mode
collective|partition`, `--cluster-batch N` (candidates per request), and
`--cluster-session FILE` to **resume** an interrupted fleet run (already-tried
candidates are skipped).

### Securing the link with TLS

Uploaded files, recovered passwords and decrypted content cross the wire to the
workers, so the link must be encrypted. `xcrackd` can terminate TLS itself, and
the client verifies it. Generate a certificate first (self-signed for an
internal fleet, Let's Encrypt for a public endpoint):

```sh
scripts/gen-selfsigned-cert.sh -o tls -h "w1.internal,10.0.0.5"   # server.crt + server.key
# or, for a public name:  scripts/gen-letsencrypt-cert.sh -d crack.example.net -m you@example.net -o tls
```

Serve HTTPS on the worker, and point the client at `https://` with the cert it
should trust:

```sh
# worker:
xcrackd -addr :8443 --tls-cert tls/server.crt --tls-key tls/server.key -gpu

# controller (trust the self-signed cert; omit --tls-ca for a public CA):
xcrack --server https://w1.internal:8443 --tls-ca tls/server.crt -w rockyou.txt big.7z
```

For **mutual TLS** (the server also authenticates each client), generate a CA +
server + client kit and require client certs:

```sh
scripts/gen-selfsigned-cert.sh -o tls -h "w1.internal" -m        # ca/server/client .crt/.key
xcrackd -addr :8443 --tls-cert tls/server.crt --tls-key tls/server.key --tls-client-ca tls/ca.crt
xcrack --server https://w1.internal:8443 --tls-ca tls/ca.crt \
       --tls-cert tls/client.crt --tls-key tls/client.key -w rockyou.txt big.7z
```

Client TLS flags: `--tls-ca` (trust a private/self-signed server cert),
`--tls-cert`/`--tls-key` (client cert for mTLS), `--tls-server-name` (verify a
name other than the URL host, e.g. when connecting by IP), and `--tls-insecure`
(skip verification — **testing only**). The same settings live under
`cluster.tls.*` in a config file. Server TLS flags: `--tls-cert`, `--tls-key`,
`--tls-client-ca` (mTLS), `--tls-min-version 1.2|1.3`.

> **Security:** TLS encrypts and authenticates the transport, but `xcrackd`
> still ships **no user authentication** — anyone who can reach the port (and
> pass mTLS, if required) can submit work. Keep it on a trusted network or
> behind an authenticating proxy, and never expose it to the internet unguarded.

See [`USAGE.md`](USAGE.md#http-service-xcrackd) for the HTTP API and the
challenge-export bridge.

---

## 5. Advanced usage

### Shape the candidate stream

- **Rules:** `--pattern FILE` (hashcat rule syntax); generate rules with
  `--generate-rules N`.
- **Masks:** `--hcmask FILE`, inline `?l?u?d?s?a?b`, custom charsets `-1..-4`
  (`?1..?4`), and length-incrementing `--increment MIN:MAX`.
- **Combinator:** `--combinator-left A --combinator-right B [--combinator-sep S]`.
- **Hybrid:** `--hybrid-append MASK` / `--hybrid-prepend MASK`.
- **Generators:** `--markov` / `--markov-pos` (best-first, position-aware) with
  `--markov-threshold`; PRINCE, toggle-case, keyboard-walk.
- **Targeted lists:** `--swedish` (embedded language list); the breach/spray/
  context sources are enabled by their flags/config.
- **Restrict:** `--min-length` / `--max-length`, `--encoding
  utf-8|latin1|utf-16le|utf-16be`.

### Hints and context

`--hint STR` and the context/association candidates derive guesses from the
filename and sibling cleartext; an embedded hint (iWork `.iwph`, ZIP comment) is
tried automatically.

### Resume long runs

- `--checkpoint FILE` — resume one long single-file run where it stopped.
- `--session FILE` — resume a whole multi-file batch (finished files skipped).

### Output and reporting

- `-o DIR` writes `DIR/<source>.extracted/` + a `manifest.json`;
  `--extract-suffix S` changes the suffix.
- `--format text|json|jsonl` and `--results-file FILE` for machine-readable
  output. Recovered passwords never appear in the structured log.

### Keep secrets off the command line

`--password-env VAR` or `--password-file FILE` (argv is visible to `ps`).

### Preview without cracking

```sh
xcrack --stdout -w words.txt --pattern r.rule FILE     # the candidate stream
xcrack --keyspace --hcmask '?a?a?a?a' FILE             # how many candidates
xcrack --benchmark FILE                                # verify rate for this file
xcrack --estimate -w words.txt FILE                    # time-to-exhaust / to-hit
```

### Embed the library

```go
import "github.com/rom/xcrack/pkg/xcrack"
res, err := xcrack.Process(ctx, r, size, candidates.Explicit("p1","p2"), xcrack.Options{Out: "./out"})
```

See [`USAGE.md`](USAGE.md#embedding-the-library) and [`design.md`](design.md).

---

## 6. Logging and the audit trail

Both `xcrack` and `xcrackd` write a single, structured log. It is an **audit
trail**: it records what was processed and, for every successful recovery, an
entry naming the file, its type and how long the crack took — so a run can be
followed step by step and kept as evidence of what was opened. The same stream
also carries the ordinary diagnostics (startup, GPU-tier status, warnings), so
one set of options governs everything a run emits.

### Where logs go, and in what shape

By default the log goes to **stderr in text** (`key=value`) form, which keeps it
separate from the machine-readable results on stdout. Three independent choices
change that:

- **Destination** — stderr (default), a **file** (`--log-file PATH`, appended,
  created `0600`), or the **system logger** (`--syslog`). Pick exactly one of
  `--log-file` / `--syslog`; `--syslog` wins if both are set.
- **Format** — `--log-format text` (default) or `--log-format json` (one JSON
  object per line, for a log pipeline / SIEM).
- **Verbosity** — `--log-level debug|info|warn|error` (default `info`).

### Command-line options

These flags are identical on `xcrack` and `xcrackd` (the server spells them with
a single dash, e.g. `-syslog`, as Go's flag package allows either form):

| Flag | Default | Meaning |
|------|---------|---------|
| `--log-level debug\|info\|warn\|error` | `info` | Verbosity. Crack successes and request summaries are **info**; the per-node / per-file trace is **debug**; transient fallbacks are **warn**. |
| `--log-format text\|json` | `text` | `key=value` lines, or one JSON object per line. |
| `--log-file PATH` | *(stderr)* | Append the log + audit trail to a file instead of stderr. |
| `--syslog` | off | Send the log + audit trail to the system logger (Unix only; a clean error elsewhere). |
| `--syslog-address host:port` | *(local socket)* | Ship to a remote syslog server. Empty uses the local `/dev/log` socket. |
| `--syslog-network udp\|tcp` | *(local socket)* | Transport for a remote `--syslog-address`. |
| `--syslog-tag NAME` | program name | The syslog tag / ident. |
| `--audit-log-password` | off | **Also record the recovered password** in the crack entry. Off by default, so the trail never persists a cleartext secret unless you ask. |

### Config-file settings

Every flag has a config-file equivalent under the `output:` block (flags still
win over the file; see [`config/README.md`](../config/README.md)):

```yaml
output:
  log_level: info            # debug | info | warn | error
  log_format: json           # text | json
  log_file: /var/log/xcrack/audit.log   # omit for stderr
  syslog: false              # true => system logger (ignores log_file)
  syslog_address: ""         # host:port for a remote sink; "" = local socket
  syslog_network: ""         # udp | tcp (with syslog_address)
  syslog_tag: xcrack         # syslog ident
  audit_log_password: false  # include the recovered password in the crack entry
```

### The log messages

Each run emits two kinds of line: **audit records** (what was processed) and
**diagnostics** (what the tool is doing). The audit records are:

| Message | Level | When | Key fields |
|---------|-------|------|------------|
| `file cracked` | info | a source file had at least one layer recovered | `file`, `type` (top-level format), `encrypted`, `cracked=true`, `size`, `time_to_crack`, `time_to_crack_ms`, `cracked_entries` (inner paths), `key_recovered` (if unlocked without a password), `passwords` (only with `--audit-log-password`) |
| `file processed` | debug | a source file finished without a recovery (plain, or still locked) | `file`, `type`, `encrypted`, `cracked=false`, `size` |
| `node scanned` | debug | one node in the decomposition tree (every file/entry) — the fine-grained execution trace | `node` (lineage), `type`, `status` (`plain`/`decrypted`/`locked`/…), `encrypted`, `size`, plus `time_to_crack`/`password` for a decrypted node |
| `request served` | info | **`xcrackd` only** — one HTTP request completed | `client`, `endpoint`, `bytes`, `elapsed` |

On `xcrackd` every audit record additionally carries `client` and `endpoint`, so
the server keeps a complete trail of who asked for what. The "file type" on the
headline is the **top-level** format (e.g. `zip`, `msoffice`, `pdf`), even when
the encryption lives in an inner stream or entry.

A cracked entry in text form (the `passwords=` field appears only with
`--audit-log-password`):

```
level=INFO msg="file cracked" file=invoice.zip type=zip encrypted=true \
  cracked=true size=0 time_to_crack=4.2s time_to_crack_ms=4200 \
  cracked_entries="[invoice.zip!/secret.xlsx]"
```

The same record as JSON (`--log-format json`), ready for a log pipeline:

```json
{"time":"2026-10-17T12:00:00Z","level":"INFO","msg":"file cracked",
 "file":"invoice.zip","type":"zip","encrypted":true,"cracked":true,"size":0,
 "time_to_crack":"4.2s","time_to_crack_ms":4200,
 "cracked_entries":["invoice.zip!/secret.xlsx"]}
```

Diagnostics use the standard levels: **info** for lifecycle lines
(`xcrackd listening`, `GPU tier active across 1 device(s)`, `shutting down`),
**warn** for transparent fallbacks (`--gpu requested but this binary is
pure-Go … Continuing on CPU`), and **error** for a failed startup or a per-file
error. Raising `--log-level debug` adds the `node scanned` trace and the engine's
own debug chatter; lowering it to `warn` keeps only warnings and errors (crack
successes are then not logged — use `info` to keep the audit trail).

### Worked examples

```sh
# Human-readable audit trail to the terminal (the default):
xcrack -s invoice.zip -w rockyou.txt

# JSON audit trail to a file, including the recovered password, for an archive:
xcrack --log-format json --log-file /var/log/xcrack/audit.log \
       --audit-log-password -s invoice.zip -w rockyou.txt

# Ship the trail to a central syslog server over TCP:
xcrack --syslog --syslog-network tcp --syslog-address logs.example.net:514 \
       --syslog-tag xcrack -s *.pdf -w words.txt

# Follow every step of a tricky run (adds the per-node trace):
xcrack --log-level debug -s nested.7z -w words.txt

# Server: JSON audit trail to local syslog, tagged, no secrets:
xcrackd -syslog -log-format json -gpu -addr :8080
```

A secrets-free trail (the default) is safe to forward to a shared log host; turn
on `--audit-log-password` only where storing the cleartext password is itself
authorized.

---

## 7. Debugging and troubleshooting

### Inspect the effective configuration

```sh
xcrack --show-config FILE       # merged flags/env/config/defaults (no secrets); then exits
xcrack --show-cache             # which passwords the found-cache holds
xcrack --show                   # which files the cache already solves  (--left = which remain)
```

### "not encrypted or unsupported"

Confirm the format: `xcrack identify FILE`. For a magic-less format (SQLCipher,
VBA) force it: `--as sqlcipher` / `--as vbaproject`. For an Access `.mdb` use
`xcrack access-recover`; an `.accdb` needs a password search.

### A run seems stuck or very slow

The KDF is probably just expensive (Argon2, scrypt, 100k-iteration PBKDF2 — see
[`PERFORMANCE.md`](PERFORMANCE.md)). Use:

```sh
xcrack --estimate -w words.txt FILE     # expected time before you commit
xcrack --progress -w words.txt FILE     # live rate / ETA to stderr
xcrack --time-limit 10m -w words.txt *  # cap per-file effort in a batch
```

### Debug rules and masks

```sh
xcrack --debug-rules --pattern r.rule -w words.txt FILE   # per-rule hit/reject stats
xcrack --stdout --pattern r.rule -w words.txt FILE        # see exactly what is generated
```

### GPU issues

```sh
bin/xcrackd-gpu -gpu-selftest     # does the device/kernel validate against the CPU reference?
```

If the self-test fails or no device is present, the tier logs why and runs on
the CPU — results are identical, only slower. Confirm you built with
`-tags opencl` and have an OpenCL runtime; use `XCRACK_GPU_DEVICE` to pick a
device.

### Logging and the audit trail

Logging has its own chapter: see [6. Logging and the audit
trail](#6-logging-and-the-audit-trail) for the flags, config settings and the
meaning of each log message. For a stuck run, `--log-level debug` adds the
per-node `node scanned` trace so you can see exactly where the engine spends its
time.

### Exit codes

`0` = at least one layer decrypted (or a clean inspection), `1` = nothing
decrypted / still locked, `2` = a usage or I/O error. See
[`USAGE.md`](USAGE.md#exit-codes).

### Still stuck?

Check [`FAQ.md`](FAQ.md) (troubleshooting + limitations), confirm the scheme is
supported in [`FILEFORMATS.md`](FILEFORMATS.md), and see how it is attacked in
[`CRACKING.md`](CRACKING.md).
