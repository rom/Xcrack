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
3. [CLI reference — commands, options and flags](#3-cli-reference--commands-options-and-flags)
4. [GPU acceleration](#4-gpu-acceleration)
5. [Distributed environments](#5-distributed-environments)
6. [Advanced usage](#6-advanced-usage)
7. [Embedding the library](#7-embedding-the-library)
8. [Logging and the audit trail](#8-logging-and-the-audit-trail)
9. [Debugging and troubleshooting](#9-debugging-and-troubleshooting)
10. [Web GUI (xcrack-web)](#10-web-gui-xcrack-web)
11. [Security](#11-security)

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

## 3. CLI reference — commands, options and flags

`xcrack` is one binary with **subcommands**. With no subcommand it runs the
default **crack** pipeline (`xcrack [flags] FILE…`); the other subcommands are
focused tools. For the exhaustive, always-current flag list run `xcrack --help`
(and `xcrack <subcommand> --help`); this chapter is the organized tour.

```
xcrack [flags] FILE…        default: identify → decrypt → recurse
xcrack <subcommand> …       a focused tool (below)
```

### Subcommands

| Subcommand | What it does |
|------------|--------------|
| *(none)* | the crack pipeline: detect, decrypt, recursively decompose, report |
| `identify` | detect format + encryption shape only; no cracking |
| `kp` | ZipCrypto **known-plaintext** key recovery (no password) |
| `hashline` | emit a `hashcat`/John hash line for a file (offload elsewhere) |
| `export-challenge` | export an encrypted target as a portable challenge envelope |
| `office-keyattack` | sweep the 40-bit RC4 key of a legacy `.doc/.xls/.ppt` (`--gpu`, `--shard`) |
| `pdf-keyattack` | sweep the 40-bit RC4 key of a PDF V1/R2 (`--gpu`, `--table`, `--shard`) |
| `thunder-gen` | build a precomputed "Thunder Table" (rainbow TMTO) for PDF R2 (`--gpu`; `--progress N%` or `N<hour\|day>` for periodic progress; writes `--out` incrementally and **resumes** it if the same command is re-run after an interrupt/crash) |
| `access-recover` | recover/strip an MS Access database password |
| `vba-recover` | recover an Office VBA project password |
| `wordlist` | wordlist utilities (dedupe, sort, length filter, …) |
| `version`, `help` | print the version / usage |

Run `xcrack <subcommand> --help` for each tool's own flags.

### Inputs

| Flag | Meaning |
|------|---------|
| `-s, --source FILE` | a target file/dir/glob (repeatable); also accepted as positional args |
| `-w, --wordlist FILE` | a wordlist; `-` = stdin; gzip auto-detected (repeatable) |
| `-p, --password PW` | an explicit candidate password (repeatable) |
| `--password-file FILE` | read candidates (one per line) from a file (repeatable) |
| `--password-env VAR` | read one candidate from an environment variable (keeps it out of `argv`) |
| `--pattern FILE` | a mask/rule pattern file (repeatable) |
| `--as SCHEME` | force a magic-less format (`sqlcipher`, `vbaproject`), bypassing detection |
| `-c, --config FILE` | a YAML config file (see [`config/README.md`](../config/README.md)) |

### Output and reporting

| Flag | Meaning |
|------|---------|
| `--format text\|json\|jsonl` | result output format |
| `-o, --out DIR` | write the decrypted tree to a directory |
| `--extract-suffix S` | per-source extracted-tree directory suffix under `--out` |
| `--results-file FILE` | write a JSON result manifest |
| `--outfile-format SPEC` | hashcat-style found-password lines (`1`=target,`2`=plain,`3`=hex) |
| `--progress` / `--status-timer N` | live rate/ETA to stderr / a heartbeat every N s |
| logging | `--log-level`, `--log-format`, `--log-file`, `--syslog…`, `--audit-log-password` — see [§8](#8-logging-and-the-audit-trail) |

### Candidate generation (how guesses are built)

| Flag | Meaning |
|------|---------|
| `--no-default-list` | disable the built-in common-password list |
| `--swedish` | also try the built-in Swedish-targeted list |
| `--breach FILE` / `--breach-min-count N` | frequency-annotated leak corpus; drop rare entries |
| `--spray` / `--spray-token T` / `--spray-year Y` | curated password-spraying set |
| `--context` | guesses from the file/entry name and plaintext sibling entries |
| `--hint` / `--hint-rules FILE` | guesses from an embedded password hint, optionally rule-mangled |
| `--pcfg` / `--pcfg-max N` | train a PCFG on the words, emit in probability order |
| `--markov` / `--markov-max N` / `--markov-threshold K` / `--markov-pos` | Markov best-first generation |
| `--order markov` / `--order-max N` | reorder the wordlist likeliest-first before mangling |
| `--combinator-left/-right/-sep` | combinator attack (each left word + each right word) |
| `--prince` / `--toggle-case` / `--keyboard-walk` | PRINCE chains / case toggles / keyboard walks |
| `--loopback` | feed cached recovered passwords back through the rules |
| `--min-length` / `--max-length` / `--encoding` | length filter / transcode candidates |

### Masks and rules

| Flag | Meaning |
|------|---------|
| `--pattern FILE` | mask/rule pattern file (repeatable) |
| `--hcmask FILE` | hashcat `.hcmask` file (per-line masks) |
| `-1`/`--custom-charset1` … `-4`/`--custom-charset4` | define custom mask charsets `?1`..`?4` |
| `--increment MIN:MAX` | expand each mask over a token-length range, shortest first |
| `--hybrid-append MASK` / `--hybrid-prepend MASK` | dict+mask / mask+dict attacks |
| `--generate-rules N` / `--generate-rules-seed S` | fold N reproducible random rules into the pool |
| `--debug-rules` | don't crack: report per-rule hit/reject stats |

### Performance, limits and recursion

| Flag | Meaning |
|------|---------|
| `--workers` / `--file-jobs` / `--max-procs` | per-file testers / files in parallel / global tester ceiling |
| `--batch-size` / `--throttle` | worker hand-off size / approximate CPU duty cycle |
| `--gpu` / `--dual-pipeline` | offload the sweep to OpenCL / race CPU+GPU (see [§4](#4-gpu-acceleration)) |
| `--timeout`/`--time-limit` / `--max-duration` | per-file budget / whole-run deadline |
| `--recurse` / `--no-recurse` / `--explode-documents` | container decomposition controls |
| `--max-depth` / `--max-nodes` / `--max-total-bytes` / `--max-entry-size` / `--max-candidates` | safety ceilings |
| `--find-all` / `--adaptive` / `--cost-queue` | search every node / corpus-wide promotion / weakest-first triage |

### Persistence and resume

| Flag | Meaning |
|------|---------|
| `--potfile FILE` | load/append recovered passwords (tried first next time) |
| `--found-cache FILE` / `--remember` | a persistent found-password cache (default location with `--remember`) |
| `--checkpoint FILE` | resume a single long run near where it stopped |
| `--session FILE` | resume a multi-file run (skip files already fully searched) |
| `--reuse-output` | with `-o`, skip a source whose extracted output is already current |
| `--resume-from FILE` | import a solved challenge envelope and try its password first |

### Distributed (see [§5](#5-distributed-environments))

| Flag | Meaning |
|------|---------|
| `--shard I/N` | test only stride *I* of *N* (manual split, no servers) |
| `--server URL[@GROUP]` | distribute to an `xcrackd` server (repeatable) |
| `--cluster-mode collective\|partition` / `--cluster-batch N` / `--cluster-allow-defaults` / `--cluster-per-request DUR` | fleet allocation and tuning |
| `--cluster-session FILE` | resume an interrupted fleet run |
| `--tls-ca` / `--tls-cert` / `--tls-key` / `--tls-server-name` / `--tls-insecure` | client TLS for `https://` servers |

### Dry-run / inspection (don't crack)

| Flag | Meaning |
|------|---------|
| `--stdout` | print the candidate stream (wordlists + rules + masks + generators) and exit |
| `--keyspace` | print the candidate keyspace size and exit |
| `--benchmark`, `-b` | measure the per-second verify rate per format and exit |
| `--estimate` | report keyspace × rate ⇒ estimated time-to-exhaust and exit |
| `--show` / `--left` | which source files the cache already solves / does not |
| `--show-config` | print the effective merged configuration (no secrets) and exit |
| `--show-cache` | list the passwords held in the found-password cache |
| `--limit N` | cap `--stdout` / `--keyspace` output |

> Precedence for every setting is **flags > environment > config file >
> defaults**; `--show-config` prints the merged result so you can see exactly
> what a run will do before committing to it.

---

## 4. GPU acceleration

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

Then point the CLI at it (see [Distributed environments](#5-distributed-environments)),
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

### D. Building the optional tiers (Linux)

Two build tags select the optional features, and the same recipe applies to all
three binaries (`xcrack`, `xcrackd`, `xcrack-web`):

- **`opencl`** — the GPU tier. The one cgo exception to the pure-Go default
  (ADR 0001): it `#include <CL/cl.h>` and links `-lOpenCL`, so it needs
  `CGO_ENABLED=1`, a C compiler, and the OpenCL headers + ICD loader.
- **`tpm`** — the TPM-sealed found-password cache ([§11.6](#116-encrypting-the-found-password-cache-tpm)).
  Pure Go: **no extra packages**, just add the tag.

Both are inert unless you ask for them at runtime (`--gpu`,
`--cache-encryption tpm`), so a tagged binary still runs fine on a host without a
GPU or TPM — it logs why and falls back.

**Fedora prerequisites** (only for the `opencl` tag):

```sh
# C toolchain + OpenCL loader and headers
sudo dnf install gcc ocl-icd-devel opencl-headers clinfo

# plus a runtime ICD for your hardware — pick what matches the box:
sudo dnf install pocl                              # CPU OpenCL: no GPU needed, ideal for testing
# AMD:    sudo dnf install rocm-opencl             # (or mesa-libOpenCL for rusticl/clover)
# NVIDIA: sudo dnf install xorg-x11-drv-nvidia-cuda   # from RPM Fusion; provides libnvidia-opencl
# Intel:  sudo dnf install intel-compute-runtime   # (Copr on some releases)

clinfo | grep -E 'Platform Name|Device Name'       # confirm a device is visible
```

(On Debian/Ubuntu the loader/headers are `ocl-icd-opencl-dev opencl-headers`;
on openSUSE `ocl-icd-devel opencl-headers`. The tag and build commands are the
same.)

**Build all three with both tiers:**

```sh
CGO_ENABLED=1 go build -tags "opencl tpm" -o bin/xcrackd    ./xcrack/cmd/xcrackd
CGO_ENABLED=1 go build -tags "opencl tpm" -o bin/xcrack     ./xcrack/cmd/xcrack
CGO_ENABLED=1 go build -tags "opencl tpm" -o bin/xcrack-web ./xcrack/cmd/xcrack-web
```

Use a single tag (`-tags opencl` or `-tags tpm`) for just one tier. `CGO_ENABLED=1`
is required only when `opencl` is in the list; a `tpm`-only build needs no C
toolchain and no packages:

```sh
go build -tags tpm -o bin/xcrackd ./xcrack/cmd/xcrackd   # TPM only, still pure Go
```

**Verify the tiers compiled in:**

```sh
bin/xcrackd -gpu-selftest        # runs the OpenCL kernel self-test, then exits
bin/xcrack office-keyattack --help   # --gpu is effective only in a -tags opencl build
```

A pure-Go binary logs *"rebuild with -tags opencl"* when you pass `--gpu` — the
quick way to tell whether the tag took. Pick a specific device with
`XCRACK_GPU_DEVICE=<name-or-vendor-substring>`. For the `tpm` tier's runtime
requirements (a TPM 2.0 device and access to `/dev/tpmrm0`), see
[§11.6](#116-encrypting-the-found-password-cache-tpm).

---

## 5. Distributed environments

A single file's keyspace, or a batch of files, can be spread across many
machines. Xcrack offers **two models that compose**, plus the GPU tier on each
worker:

- **Manual sharding** — no coordinator. Every machine runs the same command over
  a disjoint *stride* of the keyspace (`--shard I/N`). Simplest to reason about;
  you collect the winner yourself. Best for a one-off split across a handful of
  boxes you already have shells on.
- **An `xcrackd` fleet** — a controller `xcrack` process fans candidate batches
  out to worker servers and gathers the result. The controller owns candidate
  generation (so every attack type works) and the workers are stateless
  verify/KDF engines. Best for a standing cracking service, a GPU rig, or many
  files at once.

The two compose: a fleet worker can itself be GPU-accelerated, and a fleet run
can be resumed after an interruption.

### Manual sharding (no servers)

Each machine runs the same inputs over a disjoint stride of the keyspace. The
stride is deterministic, so the N shards together cover the whole keyspace
exactly once, and promoted/context/hint guesses are tried by *every* shard (they
are cheap and high-yield):

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

**Which mode?** Use **collective** for one hard file (or a few): every worker
attacks the *same* keyspace on a disjoint stride, so N workers are roughly N×
faster on that file. Use **partition** for a *batch* of files: worker groups
(`URL@GROUP`) each take different files, so a 100-file batch finishes in the time
of its slowest file rather than the sum. Groups let you aim capability at need —
put the GPU boxes in one group and the big documents on them:

```sh
# GPU group g1 takes the slow, strong-KDF documents; CPU group g2 takes the rest:
xcrack --server https://gpu1:8443@g1 --server https://gpu2:8443@g1 \
       --server https://cpu1:8443@g2 --server https://cpu2:8443@g2 \
       --cluster-mode partition --tls-ca tls/ca.crt \
       -w rockyou.txt --pattern rules.txt *.docx *.pdf
```

**The controller owns candidate generation.** Any attack from this manual works
distributed — the controller builds the full stream (wordlist + rules + masks +
Markov/PCFG + spray + …) and ships it to the workers as batches, so you do *not*
need a server-side flag for each attack type. The workers are stateless
verify/KDF engines. Point an attack at the fleet exactly as you would locally,
just adding `--server`:

```sh
# a rule + mask hybrid, run on the fleet:
xcrack --server https://w1:8443 --server https://w2:8443 --tls-ca tls/ca.crt \
       -w rockyou.txt --pattern best64.rule --hybrid-append '?d?d?d' vault.7z
```

**GPU in the fleet.** Start each GPU worker with `-gpu` (a `-tags opencl` build);
add `-dual-pipeline` so each worker also runs its CPU alongside the device
([§4](#4-gpu-acceleration)). The controller is unchanged — it just ships
candidates; each worker decides CPU/GPU locally:

```sh
# worker on a GPU box:
xcrackd-gpu -addr :8443 -gpu -dual-pipeline --tls-cert s.crt --tls-key s.key -max-procs 16
```

**Resuming.** `--cluster-session FILE` records the contiguous tried-prefix per
file, so an interrupted fleet run restarts without re-trying confirmed work
(cross-worker, cross-run). Pair it with `-o DIR` to collect decrypted output.

Key flags: `--server URL[@GROUP]` (repeatable), `--cluster-mode
collective|partition`, `--cluster-batch N` (candidates per request),
`--cluster-per-request DUR` (per-request server deadline), `--cluster-allow-defaults`
(let each worker also try its own default list), and `--cluster-session FILE`.

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

## 6. Advanced usage

The default run already does a lot — identify, decrypt, recurse, promote
recovered passwords inward. This chapter is the toolbox for the hard cases:
shaping exactly which guesses are tried, spending effort where it pays, and
surviving long runs. Every technique here also works distributed ([§5](#5-distributed-environments))
and composes with the others.

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

### Spend effort where it pays (many files)

Triaging a pile of files? Don't attack them in argument order:

- `--cost-queue` benchmarks each file's verify rate and attacks the
  **fastest/weakest** schemes first, so the quick wins (ZipCrypto, legacy Office,
  low-iteration KDFs) surface before the slow, strong KDFs tie up the CPU.
- `--adaptive` promotes a password recovered from *any* file to the front of the
  queue for the rest (people reuse passwords), smallest files first so the cheap
  wins seed the corpus early.
- `--time-limit DUR` caps per-file effort so one Argon2 vault can't starve the
  batch; a timed-out file is reported *locked*, not failed, and the batch moves on.

### Reuse what you have already found

- `--potfile FILE` / `--found-cache FILE` / `--remember` persist recovered
  passwords and try them **first** on every later run — a reused password is then
  recovered instantly. `--loopback` additionally feeds those recovered passwords
  back through the mangling rules.
- `--show` / `--left` report which files the cache already solves / doesn't,
  without cracking; `--show-cache` lists the cached passwords.

### Offload to another cracker

When a scheme is better attacked by hashcat/John (or a GPU rig you don't control
from here), bridge instead of cracking in-engine:

```sh
xcrack hashline secret.7z                 # emit a $7z$… / *2john hash line
xcrack export-challenge vault.kdbx -o chal.json   # a portable challenge envelope
# …solve chal.json elsewhere, then:
xcrack --resume-from solved.json vault.kdbx       # import the password and finish
```

### Preview without cracking

```sh
xcrack --stdout -w words.txt --pattern r.rule FILE     # the candidate stream
xcrack --keyspace --hcmask '?a?a?a?a' FILE             # how many candidates
xcrack --benchmark FILE                                # verify rate for this file
xcrack --estimate -w words.txt FILE                    # time-to-exhaust / to-hit
xcrack --debug-rules --pattern r.rule -w words.txt FILE # per-rule hit/reject stats
```

### Worked advanced examples

```sh
# 1. Wordlist + hashcat rules, newest finds cached for next time:
xcrack -w rockyou.txt --pattern best64.rule --remember vault.zip

# 2. Targeted mask with custom charsets and length incrementing:
xcrack -1 '?l?u' -2 '?d?s' --increment 6:10 --hcmask '?1?1?1?1?2?2' doc.pdf

# 3. Hybrid: each dictionary word followed by a 2-to-4 digit suffix:
xcrack -w names.txt --hybrid-append '?d?d' --hybrid-append '?d?d?d?d' wallet.json

# 4. Markov best-first, position-aware, capped — great when the wordlist is thin:
xcrack -w leaked.txt --markov-pos --markov-max 5000000 --markov-threshold 12 big.7z

# 5. Spray a target org's vocabulary with season/year patterns:
xcrack --spray --spray-token acme --spray-token finance --spray-year 2024 portal.docx

# 6. Context: let the filename and any cleartext siblings seed the guesses:
xcrack --context --hint -w small.txt "Invoice for ACME (password in email).zip"

# 7. Combinator: every first-name + every street, joined by '.':
xcrack --combinator-left first.txt --combinator-right streets.txt --combinator-sep . kdbx

# 8. Resume a huge single-file run safely across restarts:
xcrack --checkpoint run.ckpt -w huge.txt --pattern rules.txt stubborn.7z

# 9. Force a magic-less format, throttle to be gentle on a shared host:
xcrack --as sqlcipher --throttle 40 -w words.txt app.db

# 10. Batch triage: weakest-first, per-file cap, cache finds, JSON manifest:
xcrack --cost-queue --time-limit 5m --remember --format json --results-file out.json *.zip *.pdf *.docx
```

---

## 7. Embedding the library

Xcrack is also an embeddable Go library (`github.com/rom/xcrack/pkg/xcrack`) with
the **same capability as the CLI** — a malware scanner, a DLP appliance or a
recovery service runs the engine in-process instead of shelling out. This is a
tour; the full reference is [`API.md`](API.md), and runnable programs live in
[`xcrack/examples/`](../xcrack/examples).

### The shape of an embedding

Build one **`Pool`** at startup and reuse it; its global semaphore bounds total
CPU across every concurrent `Process` call, so it is safe to call from many
request goroutines:

```go
pool := xcrack.NewPool(xcrack.Options{
    MaxProcs: 8,
    Budget:   xcrack.Budget{PerFile: 30 * time.Second},
    OnFound:  func(f xcrack.Found) { log.Printf("unlocked %s", f.Path) },
})
defer pool.Close()

res, err := pool.Process(ctx, bytes.NewReader(data), int64(len(data)),
    candidates.Explicit("letmein", "hunter2"))
if err != nil { /* ... */ }
defer res.Close()
for _, pw := range res.Passwords() { /* ... */ }
```

`xcrack.Process(ctx, r, size, src, opts)` is the one-shot form (a single-use
Pool). Pass `nil` candidates for identify-only.

### Options and candidate sources

Every CLI flag maps to a field on `xcrack.Options` (concurrency, `Limits`,
`Budget`, recursion toggles, `ContextCandidates`/`HintCandidates`,
`KnownPlaintext`, `FastReject`, `Accelerator`/`DualPipeline`, the `OnFound` /
`OnProgress` / `OnAudit` callbacks, `Logger`). Candidate streams are composed from
`github.com/rom/xcrypto/candidates` — `Explicit`, `File`, `Chain`, `Dedup`,
`Shard`, `ToggleCase`, `Prince`, `MarkovGen`, `Context`, `Spray`, … — exactly the
generators the CLI flags drive. [`API.md`](API.md) documents every field and
constructor.

### What you get back

`Process` returns a `*Result` with a `Root *Node` tree (lineage, format, status,
`Password`, per-node `CrackDuration`, lazy `Content` via `ContentRef`) and
`Stats`. `res.Passwords()` lists the distinct recoveries; `Node.Walk` traverses
the tree; `BuildReport(res)` renders the same JSON the REST API returns.

### Advanced hooks

- **`CandidateProvider`** — plug a live/org-wide candidate source once instead of
  threading it through every call.
- **`FastReject`** — prune a hopeless keyspace before the KDF (e.g. "the secret
  is a 6-digit PIN").
- **`KnownPlaintext`** — recover a ZipCrypto entry from known plaintext, no password.
- **`Accelerator` + `DualPipeline`** — offload the PBKDF2 sweep to the OpenCL tier
  and race it against the CPU.
- **`auditlog`** — build the structured/syslog logger the tools use.

### Example programs

| Example | Shows |
|---------|-------|
| [`impex-embed`](../xcrack/examples/impex-embed) | the minimal embedding: one Pool, in-memory candidates, `OnFound` |
| [`batch-triage`](../xcrack/examples/batch-triage) | concurrent triage of many files, JSON per file, aggregate `Metrics` |
| [`candidate-pipeline`](../xcrack/examples/candidate-pipeline) | composing an advanced candidate stream + `CandidateProvider` |
| [`pin-fastreject`](../xcrack/examples/pin-fastreject) | `FastReject` keyspace pruning + a custom `Source` |
| [`inspect-tree`](../xcrack/examples/inspect-tree) | identify-only traversal of the `Result`/`Node` tree |
| [`http-service`](../xcrack/examples/http-service) | embedding the REST API (`pkg/api`) in your own server |

See [`API.md`](API.md) for the complete API and [`design.md`](design.md) for the
architecture.

---

## 8. Logging and the audit trail

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

## 9. Debugging and troubleshooting

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

Logging has its own chapter: see [8. Logging and the audit
trail](#8-logging-and-the-audit-trail) for the flags, config settings and the
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

---

## 10. Web GUI (xcrack-web)

`xcrack-web` is a browser front-end to the engine: the same recovery power as
the CLI, reachable from a graphical interface. It is a single self-contained
binary that embeds the engine **and** the web assets, so there is nothing to
install alongside it and it works offline.

Every feature the CLI configuration file can express is reachable from the GUI,
because the GUI builds the *same* job description (`jobspec.Spec`, the YAML the
`--config` flag consumes) and runs it through the same engine wiring.

### 10.1 Running it

```sh
make web                     # build bin/xcrack-web
bin/xcrack-web               # serve on http://127.0.0.1:8899 (localhost only)
# or:
bin/xcrack-web --addr :9000  # listen on all interfaces (see the security note)
```

Open the printed URL. The binary auto-detects a `docs/` directory next to it and
serves this manual (and the rest of the docs) inside the app; point it elsewhere
with `--docs-dir`.

| Flag | Meaning |
|------|---------|
| `--addr` | listen address (default `127.0.0.1:8899`; use `:PORT` for all interfaces) |
| `--docs-dir DIR` | Markdown docs to serve in the **Docs** tab (default: auto-detect `./docs`) |
| `--work-dir DIR` | where per-job uploads and extracted output live (default: a temp dir) |
| `--max-upload N` | maximum job-submission size in bytes (default 512 MiB) |
| `--expose-secrets` | show recovered passwords in the UI/stream (default on; see below) |
| `--allow-server-paths` | let a job reference server-side files, not just uploads (trusted local use only) |
| `--tls-cert` / `--tls-key` | serve HTTPS (see [5. Distributed environments](#5-distributed-environments) for the cert scripts) |
| `--tls-client-ca` | require client certificates (mutual TLS) |

### 10.2 Easy mode, advanced mode and the Configuration view

- **Easy mode** (default) is a guided form: drop the locked file(s), pick a
  wordlist, tick the candidate sources and generators (masks, rules, Markov,
  PRINCE, toggle-case, keyboard-walk, name/sibling context, embedded hint), and
  press **Run**.
- **Advanced mode** (the toggle in the header) expands the Crack form with the
  full engine surface in grouped, collapsible panels: concurrency &
  acceleration, search behaviour, generators & ordering (Markov/PCFG, order,
  increment, hybrid, combinator, hint-rules), candidate lists (spray, breach,
  password files, length, encoding, Swedish), patterns (custom charsets ?1–?4,
  .hcmask, generate-rules), limits & budget, recursion/input/output (force-
  format, output format, the TPM-sealed cache), **Distributed cracking**, and an
  auxiliary-file uploader.
- **Configuration view** (its own tab) holds the **IDE-style YAML editor** for
  the job configuration — line numbers, syntax highlighting, **Validate**,
  **Format**, and **↤ From form** (fill the editor from the Crack form). Tick
  *Run from the YAML below* to use the document verbatim instead of the form.
  The schema is exactly the one in [`config/README.md`](../config/README.md).
  This view also has the **Appearance** theme picker (see §10.6).

Every setting carries a **hover tooltip** explaining what it does (e.g. what a
Markov generator is, or that "max candidates 0" means unlimited).

### 10.3 Distributed cracking from the GUI

The **Distributed cracking** panel (advanced mode) fans the search out to a
fleet of `xcrackd` servers instead of cracking locally: list the server URLs
(append `@group` for partition groups), pick collective or partition mode, set
the batch size / per-request deadline, and configure TLS (CA, client cert for
mutual TLS, SNI, insecure toggle). Because this makes the server connect out to
the configured endpoints, it is only honoured when `xcrack-web` was started with
`--allow-server-paths` (a trusted, local instance); otherwise the job is
rejected. Passwords are recovered on the servers; decrypted content stays there,
so a distributed run reports passwords without a local download.

### 10.4 Running a job

Progress streams live over Server-Sent Events (nothing is polled). The running
job shows the **start timestamp**, a ticking **elapsed** clock, a **progress
bar** (a true percentage against the keyspace for a single finite-keyspace
target, otherwise an indeterminate sweep), the **latest candidate/term** being
tested, live throughput, the engine log, and each recovered password as it is
found. When a file is unlocked its decrypted contents can be **downloaded** as a
zip of the extracted tree.

**Previewing a wordlist:** next to each uploaded wordlist (or auxiliary file) a
**Preview** button shows the first lines of the `.txt` in a dialog, so you can
check a list before launching the run.

### 10.5 Tools (specialist subcommands)

The **Tools** tab surfaces the CLI's specialist, non-cracking subcommands
(§[3](#3-command-reference)) without leaving the browser. The quick, stateless
operations run in-engine against the `/api/v1/tools/*` endpoints and return
right away:

- **Identify** — detect each file's format and whether it is encrypted, a
  container, or explodable (the `identify` subcommand).
- **Hash lines** — emit `$office$`/`$pdf$`/`$zip2$`/`$keepass$`… lines for
  hashcat / John, with the hashcat mode and John format shown (`hashline`).
- **VBA project password** — recover a VBA project-protection password (plaintext
  or a crackable salted-SHA-1 line) from an Office carrier or `vbaProject.bin`.
- **Access (Jet) password** — read a Jet (`.mdb`) database password straight from
  the header (no cracking).
- **Export challenge** — download the portable JSON challenge envelope(s) to
  solve on an external cracker, then bring the result back with `--resume-from`.
- **PDF 40-bit key (thunder table)** — invert a V1/R2 PDF's file key instantly
  by uploading the PDF and a precomputed thunder table (the `pdf-keyattack
  --table` fast path).
- **Wordlist utilities** — length-filter, dedupe, sort, sort-by-length, or split
  a wordlist (upload or paste); split downloads a zip of equal parts.

The long compute jobs — a full 2⁴⁰ `pdf-keyattack` / `office-keyattack` sweep
and `thunder-gen` table generation — are **not** run from the browser; instead
the tab builds the exact CLI command from a small form (with `--gpu`, workers,
sharding, progress, table-generation knobs, …) for you to copy and run on the
CLI or the distributed tier. Recovered secrets (keys, VBA/Access passwords) are
shown only when the server was started with `--expose-secrets`; otherwise a
redaction marker stands in, exactly as on the crack path.

### 10.6 Statistics

The **Statistics** tab shows the aggregate counters across jobs (files
processed, candidates tried, decrypted vs. still-locked), a live candidate-
throughput chart for the running job, a **speed-by-algorithm/cipher** table
(per-format candidate throughput measured from finished jobs), and a **top
recovered passwords** list (most frequently recovered, when the server exposes
secrets).

### 10.7 Appearance (themes) and in-app documentation

The **Configuration** tab's Appearance picker offers six themes plus System
(which follows your OS light/dark setting): **Light**, **Dark**, **Glow**,
**Gold**, **Autumn** and **Spring**. The choice is remembered in the browser.
The **Docs** tab renders this manual and the reference docs as formatted pages,
so the full documentation travels with the GUI.

### 10.8 Security

`xcrack-web` ships no authentication and, bound to localhost (the default), is a
single-user console; exposing it on a network needs a proxy and TLS. Its
security model, how to enable TLS, and the TPM-sealed cache are covered in
[11. Security](#11-security) — see [§11.4](#114-the-web-gui-xcrack-web),
[§11.5](#115-enabling-tls) and [§11.6](#116-encrypting-the-found-password-cache-tpm).

---

## 11. Security

Xcrack recovers access to files you are authorized to access. This chapter
describes what it defends against, the security of each delivery form, how to
enable TLS, and how to seal the found-password cache to a TPM.

### 11.1 Threat model

**What Xcrack is.** A defensive / recovery tool that takes an untrusted,
possibly hostile input file and a set of password candidates and produces a
verified tree of decrypted content. The two things it handles are therefore
both sensitive: the **input files** (attacker-controlled bytes fed to parsers)
and the **recovered secrets** (passwords, keys, decrypted content).

**Hostile input is the primary adversary.** Every format parser treats its
input as hostile: container decomposition is bounded (depth, node count,
cumulative and per-entry size, decompression ratio — see `limits:`) to defuse
zip-bombs and quadratic blow-ups, parsers are fuzzed with committed crashers
replayed on every CI run, and large inputs stream to disk rather than being held
in memory. A malformed or malicious file should be rejected or safely bounded,
never crash the process or exhaust the host.

**Correctness is adversarial too.** Every cryptographic scheme is cross-checked
against an external oracle, and every GPU/table "hit" is re-verified by the
format's own CPU verifier before it is reported — so an accelerator bug or a
crafted table can never cause a false positive.

**What Xcrack does *not* defend against.** It is not a sandbox: run it on inputs
you are authorized to process, as a user with no more privilege than the task
needs. It does not protect recovered secrets once you have asked for them — a
results file, an audit log with `--audit-log-password`, or an on-screen password
is yours to protect. The network services (`xcrackd`, `xcrack-web`) **ship no
authentication or authorization**; that is the operator's responsibility (below).
Side-channel resistance (timing, power) of the cracking primitives is out of
scope — Xcrack attacks crypto, it is not a constant-time secrets vault.

### 11.2 The CLI (`xcrack`) and the library

`xcrack` runs locally with the privileges of the user who invokes it; there is
no network surface. Keep secrets off the command line (visible to `ps`): prefer
`--password-file`, `--password-env`, or the found-password cache over `-p`. The
audit trail is secrets-free by default — the recovered password is recorded only
with `--audit-log-password` (see [8. Logging](#8-logging-and-the-audit-trail)).
Output written with `-o` is guarded against path traversal (a malicious entry
name cannot escape the output directory). The embeddable library (`pkg/xcrack`)
has the same posture: an embedder chooses whether `OnFound`/the result tree —
which carry recovered passwords — cross a trust boundary, and applies its own
access control if so.

### 11.3 The HTTP service (`xcrackd`)

`xcrackd` is a hardened, headless backend meant to run on a trusted host and be
called by a thin client. It **ships no authentication**, holds no state beyond
the shared engine pool, and must never be exposed directly to an untrusted
network. In front of it, place authentication/authorization (a reverse proxy, a
mesh, mutual TLS) and transport security. Request bodies are bounded
(`--max-body`) and handed to the same hostile-input-safe parsers as the CLI;
per-request deadlines bound processing. Recovered passwords appear in responses
and are logged only when the operator opts in (`--audit-log-password`). It can
terminate TLS itself (next section) or sit behind a TLS-terminating proxy.

### 11.4 The web GUI (`xcrack-web`)

`xcrack-web` has the same "no built-in auth" posture as `xcrackd`. Bound to
localhost (the default `127.0.0.1:8899`) it is a single-user console on your own
machine. If you bind a non-localhost address it warns on startup, because it is
then reachable by others with no authentication: put it behind an authenticating
reverse proxy and enable TLS, and pass `--expose-secrets=false` so recovered
passwords do not appear in the shared UI or event stream.

A submitted job may reference **only the files uploaded with it**: every
file-path field in the job spec is resolved within that job's upload area and
anything absolute or traversing is rejected. `--allow-server-paths` relaxes this
to allow server-side paths and is for a trusted, local single-user instance
only. Output destinations named in a spec are ignored — the backend chooses
where results are written. Uploads are bounded by `--max-upload`.

### 11.5 Enabling TLS

Both network binaries terminate TLS the same way. First generate a certificate:

```sh
# self-signed (and, with -c, a full mutual-TLS kit: server + client + CA):
scripts/gen-selfsigned-cert.sh -o tls -d crack.internal
# or a real certificate for a public name via Let's Encrypt / ACME:
scripts/gen-letsencrypt-cert.sh -d crack.example.net -m you@example.net -o tls
```

Then serve HTTPS:

```sh
# xcrackd:
bin/xcrackd --addr :8443 --tls-cert tls/server.crt --tls-key tls/server.key
# xcrack-web:
bin/xcrack-web --addr :8443 --tls-cert tls/server.crt --tls-key tls/server.key
```

Add `--tls-client-ca tls/ca.crt` to require and verify client certificates
(mutual TLS), and `--tls-min-version 1.3` to raise the floor from the TLS 1.2
default. The `xcrack` distributed client trusts a private server cert with
`--tls-ca` and presents its own cert with `--tls-cert`/`--tls-key`; see
[5. Distributed environments](#5-distributed-environments) for a fleet example.
Enabling the binary's own TLS is independent of any outer proxy — use whichever
fits your deployment, but never expose plaintext on an untrusted network.

### 11.6 Encrypting the found-password cache (TPM)

The found-password cache (the "potfile": passwords recovered on earlier runs,
tried first on later ones — `--found-cache`/`--remember`/`--potfile`) can be
encrypted at rest, with its key sealed to the host's TPM so the file is useless
if copied off the machine:

```sh
# Requires a binary built with -tags tpm on a host with a TPM 2.0 device.
bin/xcrack --remember --cache-encryption tpm -w rockyou.txt secret.docx
```

or in the config file:

```yaml
output:
  cache_encryption: tpm   # "" / "none" (plaintext, the default) or "tpm"
```

How it works: the cache is encrypted with AES-256-GCM under a random
data-encryption key, and that key is TPM-sealed under a storage primary unique
to the machine's TPM. A cache file copied to another host — or tampered with —
fails to unseal/authenticate and is rejected (the run aborts rather than
silently discarding your cache). TPM support is compiled in only with
`-tags tpm`; the default pure-Go build reports a clear error if you ask for it,
so you are never left believing the cache is protected when it is not. A
plaintext cache remains the default and is unchanged. See
[§4.D](#d-building-the-optional-tiers-linux) for how to build the `tpm` tier (it
needs no extra packages) and the runtime device access it expects:
`/dev/tpmrm0`, typically group `tss`.

> Authorized use only: operate on files you own or are permitted to access.
