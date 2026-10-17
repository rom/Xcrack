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
6. [Debugging and troubleshooting](#6-debugging-and-troubleshooting)

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

The GPU tier is an **opt-in, server-only** exception to the pure-Go default: the
`xcrack` CLI is always CPU-only. There are two ways to use a GPU.

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

### B. The server tier (`xcrackd --gpu`) for the live crack loop

`xcrackd` can offload the heavy per-candidate KDF of a normal password search to
the GPU. Build and self-test it first:

```sh
go build -tags opencl -o bin/xcrackd-gpu ./xcrack/cmd/xcrackd
bin/xcrackd-gpu -gpu-selftest           # prove the kernels match the CPU reference, then exit
bin/xcrackd-gpu -gpu -addr :8080        # hardware-gated; falls back to CPU if no device
```

Then point the CLI at it (see [Distributed environments](#4-distributed-environments)),
or POST files to the HTTP endpoint.

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

> **Security:** `xcrackd` ships **no authentication or TLS** by design. Run it
> only on a trusted network, or put your own authn/TLS proxy in front. Never
> expose it to the internet.

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

## 6. Debugging and troubleshooting

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

### Logging

`--log-level debug|info|warn|error` controls the structured log (never emits a
password or plaintext). `--log-format text|json`.

### Exit codes

`0` = at least one layer decrypted (or a clean inspection), `1` = nothing
decrypted / still locked, `2` = a usage or I/O error. See
[`USAGE.md`](USAGE.md#exit-codes).

### Still stuck?

Check [`FAQ.md`](FAQ.md) (troubleshooting + limitations), confirm the scheme is
supported in [`FILEFORMATS.md`](FILEFORMATS.md), and see how it is attacked in
[`CRACKING.md`](CRACKING.md).
