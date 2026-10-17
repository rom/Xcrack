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
- [Use cases](#use-cases)
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

## Use cases

Xcrack is one engine behind a library, a CLI, and a service, so the same
recovery powers very different jobs. The scenarios below map each job to the
commands and flags that fit it; the sections further down explain every flag in
detail.

### 1. Malware-analysis preprocessing (the primary role)

A scanner (Impex) meets a password-protected or encrypted file and must see the
real content to analyse it. Embed the library and hand it the candidates you
already have (sender address, email body words, the lure's own filename), or
call the CLI/service for one-off triage.

```sh
# Decrypt + recursively unpack a suspicious attachment, writing the tree to ./out.
# --context seeds guesses from the file/entry names and any plaintext siblings
# (phishing lures very often name their own password in the covering email/README).
xcrack --context -p infected -p 2024 -w rockyou.txt -o ./out suspicious.zip
```

The engine unpacks nested layers on its own — an encrypted document inside an
encrypted archive is found in one pass — and reports the password **and**
content for every layer. Embedding is shown under
[Embedding the library](#embedding-the-library).

### 2. DFIR / incident response — bulk-triage a corpus

You have thousands of files off a seized image and limited time. Triage
weakest-first, cap the effort per file, and remember everything you crack so a
reused password is instant on the next batch.

```sh
# Benchmark each file, attack the cheap/weak schemes first, give up on any one
# file after 2 min, and persist finds to a shared cache.
xcrack --cost-queue --time-limit 2m --remember -w rockyou.txt -o ./out ./evidence/**
# Resume the whole batch later; already-searched files are skipped:
xcrack --session case42.session --cost-queue --remember -w rockyou.txt ./evidence/**
```

### 3. Forgotten-password recovery (a single document)

Your own `.docx`/`.pdf`/`.kdbx` with a password you half-remember. Start from a
stem and let the rules mangle it, and estimate the time before committing.

```sh
xcrack --estimate -w base-words.txt --pattern leet.rule mydoc.docx   # how long?
xcrack -w base-words.txt --pattern leet.rule --loopback mydoc.docx   # then crack
```

### 4. Authorized pentest / red-team

Spray a curated set with org/product tokens, fold in a breach corpus, and apply
your rule set — all frequency-ordered so the likely guesses go first.

```sh
xcrack --spray --spray-token Acme --spray-token Helpdesk \
       --breach top-passwords.txt --breach-min-count 50 \
       -w corp-words.txt --pattern best64.rule -o ./out export.7z
```

### 5. Recover *without* cracking (exploit a weakness first)

Some formats don't need a search at all — try these before a brute force:

```sh
xcrack kp --plain known.bin --cipher entry.bin --decrypt secret.txt \
          --zip archive.zip --zip-out ./out        # ZipCrypto: one recovery unlocks all entries
xcrack office-keyattack legacy.doc                 # Office 97/2000: sweep the 40-bit key
xcrack pdf-keyattack scanned.pdf                   # PDF V1/R2: sweep the 40-bit file key
xcrack access-recover database.mdb                 # Access Jet: read the password out of the header
```

See [`CRACKING.md`](CRACKING.md) for which weakness applies to which format.

### 6. Offload the heavy KDFs (GPU box / hashcat / John)

Keep orchestration in Xcrack but run the expensive key derivation elsewhere.

```sh
xcrack hashline target.pdf > hashes.txt            # emit $pdf$/$office$/$zip2$/$dmg$ for hashcat/John
xcrack export-challenge target.kdbx > challenge.json
# ... solve it on the GPU box, then re-import the recovered password ...
xcrack --resume-from solved.json -o ./out target.kdbx
```

The `xcrackd` service also has an opt-in in-process OpenCL tier (`--gpu`).

### 7. Distributed cracking across a fleet

Fan one keyspace out across a pile of `xcrackd` workers, or split manually with
`--shard` on fully separate hosts.

```sh
xcrack --server http://w1:8080 --server http://w2:8080 --cluster-mode collective \
       --cluster-session fleet.session -w rockyou.txt -o ./out big.7z
```

### 8. A backend service for a kiosk / appliance

Run `xcrackd` and let a thin client POST files to decrypt.

```sh
xcrackd -addr :8080 -max-procs 16
curl -s --data-binary @invoice.zip 'http://localhost:8080/v1/decrypt?password=infected'
```

### 9. Inspect before you commit (no cracking)

Preview the plan, the keyspace, and the exact effective settings before a long
run — and check what you already know.

```sh
xcrack --show-config -w rockyou.txt --pattern best64.rule target.zip  # effective settings
xcrack --keyspace    -w rockyou.txt --pattern best64.rule             # how many candidates
xcrack --stdout      -w rockyou.txt --pattern best64.rule | less      # the actual stream
xcrack --show-cache  --remember                                       # what's in the found cache
xcrack --show        --remember ./evidence/**                         # which files the cache already solves
```

---

---

## CLI

```
xcrack [flags] [sources...]      decrypt and recursively decompose sources
xcrack identify [sources...]     detect format & encryption only (no cracking)
xcrack hashline [sources...]     emit $office$/$pdf$/$zip2$ hash lines for hashcat / John
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
list, the spray set, each breach corpus, then each wordlist (expanded by any
mangling rules), then mask keyspaces. A recovered password is **promoted** to
the front for inner layers, so a nested archive that reuses a password is
unlocked almost for free.

| Flag | Meaning |
| ---- | ------- |
| `-p`, `--password STR` | an explicit candidate — repeatable |
| `-w`, `--wordlist FILE` | a wordlist; `-` reads stdin; `.gz` auto-detected — repeatable |
| `--pattern FILE` | a mask/rule pattern file — repeatable (see [Pattern engine](#pattern-engine-masks--rules)) |
| `--password-file FILE` | candidate passwords, one per line, tried first — repeatable (keeps secrets off the command line) |
| `--password-env VAR` | a candidate password read from an environment variable (not visible in `ps`) |
| `--potfile FILE` | load recovered passwords from `FILE` (tried first everywhere) and append newly recovered ones |
| `--context` | seed guesses from the file/entry name and plaintext harvested from plain sibling entries (see [Context candidates](#context-candidates)) |
| `--hint` | derive guesses from a file's embedded password hint (iWork `.iwph`, ZIP comment), tried first (see [Hint candidates](#hint-candidates)) |
| `--hint-rules FILE` | hashcat-style rule file applied to hint-derived words (implies `--hint`) |
| `--hybrid-append MASK` | append every expansion of `MASK` to each wordlist word (hashcat dict+mask, `-a 6`) — repeatable |
| `--hybrid-prepend MASK` | prepend every expansion of `MASK` to each wordlist word (hashcat mask+dict, `-a 7`) — repeatable |
| `--breach FILE` | a frequency-annotated breach corpus (`<count> <pw>` or `<pw>:<count>`; gzip auto-detected), tried ahead of plain wordlists — repeatable |
| `--breach-min-count N` | drop breach entries seen fewer than `N` times (spray only the common ones) |
| `--adaptive` | corpus-wide promotion across a multi-file run: a password recovered from any file is tried first on all the others (ordered by how often it has worked), and the smallest files are processed first so cheap wins seed the rest |
| `--shard I/N` | distributed cracking: test only shard `I` of `N` of the keyspace (0-based). Run `0/N`…`N-1/N` on separate machines/processes over the same inputs; each covers a disjoint stride and together they cover everything. Promoted/context/hint guesses are tried by every shard |
| `--spray` | add a compact curated spray set (globally common passwords + season/year walks), tried early |
| `--spray-token STR` | an org/product/user token mangled into the spray set (year, `!`/`@`/`#` suffixes, case variants) — repeatable, implies `--spray` |
| `--spray-year N` | year used in spray patterns — repeatable (default: current and previous) |
| `--pcfg` | train a PCFG on the candidate words and emit guesses in probability order (`--pcfg-max N` caps how many) |
| `--markov` | train a Markov model on the candidate words and emit guesses best-first (`--markov-max N` caps how many) |
| `--order markov` | reorder the wordlist candidates so the statistically likeliest words are tried first (`--order-max N` caps how many are buffered); distinct from `--markov`, which *generates* |
| `--swedish` | also try the built-in Swedish-targeted wordlist (common Swedish words/names/places + typical mutations, ordered most-probable-first) |
| `--resume-from FILE` | import a recovered-password envelope (from an external cracker that solved an exported challenge) and try its password first — repeatable |
| `--increment MIN:MAX` | expand each mask (from `--pattern`/config) into shortest-first prefix masks over the token-length range (hashcat `--increment`) |
| `-1`/`-2`/`-3`/`-4` STR (aka `--custom-charset1..4`) | define mask custom charsets `?1`–`?4` on the command line (hashcat `-1..-4`), used by `--hcmask`/`--pattern` masks; wins over any `?1..?4` from a pattern file/config |
| `--generate-rules N` | fold `N` reproducible random mangling rules into the rule pool (hashcat `-g`); `--generate-rules-seed S` fixes the seed |
| `--combinator-left FILE` / `--combinator-right FILE` / `--combinator-sep S` | combinator attack: every left word + every right word, optional separator (hashcat `-a 1`) |
| `--as SCHEME` | force a scheme for an input with no magic bytes (or a carrier-embedded one), bypassing detection: `sqlcipher`, `vbaproject` |
| `--checkpoint FILE` | persist/resume the search position for a long single-target run (see [Checkpoint / resume](#checkpoint--resume)) |
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

# A lure archive whose README/body names the password, or an entry named
# after its own password: let the engine seed guesses from context:
xcrack --context phishing-email.eml

# Password spraying for an authorized engagement: common + "Acme<year>" patterns:
xcrack --spray --spray-token Acme protected.docx

# A frequency-ordered breach corpus (HIBP-style "pw:count" or SecLists "count pw"),
# only trying passwords seen at least 100 times:
xcrack --breach leaked-passwords.txt.gz --breach-min-count 100 archive.zip

# Distributed cracking: split one big keyspace across four machines. Each runs
# the same command over the same inputs with a different shard; exactly one
# finds the password, the rest exhaust their stride.
xcrack --shard 0/4 -w huge.txt big.zip   # machine 0
xcrack --shard 1/4 -w huge.txt big.zip   # machine 1  (… 2/4, 3/4 on the others)
```

Sharding composes with the challenge envelope (`xcrack hashline` / the
`xcrackd` service) so a file is probed once and the heavy search is fanned out:
every worker loads the same inputs and `--shard I/N` restricts it to a disjoint
1/N stride of the candidate keyspace. The stride (every N-th candidate, not N
contiguous blocks) keeps a most-likely-first ordering spread across all shards,
so no single worker gets all the good guesses.

#### Context candidates

With `--context`, before falling back to the general keyspace the engine tries
guesses drawn from the material around each encrypted node:

- **The name** of the file or entry — its stem, alphanumeric tokens, their
  concatenation, and any digit runs (so `invoice_2024.zip` yields `invoice`,
  `2024`, `invoice2024`, …). Malware lures very often name the password after
  the file.
- **Plaintext harvested from plain sibling entries** — a `readme.txt`,
  `password.txt`, or an email body that says *"the password is …"*. The engine
  scans harvested text for hint keywords (`password`, `passphrase`, `pwd`,
  `pin`, `code`, `key`, …) and captures the following token or quoted string.

Context guesses are tried **after** promoted passwords (those recovered from an
outer layer) and **before** wordlists/masks, so the cheap, likely hits come
first. Harvesting is bounded (64 KiB per plain entry, 256 KiB per container) and
reads only *unencrypted* siblings. The feature is **off by default** (it widens
the search a little); enable it per run with `--context` or in a config file
with `search: { context_candidates: true }`.

#### Hint candidates

Some formats carry an in-file **password hint** that the author set — Apple
iWork stores one in a `.iwph` member, and a ZIP entry can have a comment. The
hint is often the password itself or a thin clue. With `--hint`, the engine
derives candidates from it and tries them **first** (right after promoted
passwords): the literal hint, its alphanumeric tokens and their concatenation,
embedded digit runs, and any value the hint quotes or names (`pw: hunter2`).

`--hint-rules FILE` (or `search: { hint_rules: [...] }`) applies a
hashcat-style ruleset to each hint-derived word, so a hint like `sesame` also
tries `Sesame`, `SESAME`, `Sesame!`, `Sesame2024`, `s3s4m3`, … — exactly the
rule DSL used by `--pattern`. Giving `--hint-rules` implies `--hint`.

```sh
# Unlock an iWork doc straight from its .iwph hint (often the password):
xcrack --hint protected.pages

# Treat the hint as a stem and mangle it into likely passwords:
xcrack --hint --hint-rules rules/best64.rule secret.zip
```

The hint is untrusted, attacker-influenced text; only candidate strings are
derived from it. The feature is **off by default**. See
[`config/hint-and-context.yaml`](../config/hint-and-context.yaml) for a worked
config.

#### Checkpoint / resume

A long run against a single hard target can be made resumable with
`--checkpoint FILE`:

```sh
# Start a long masked search, persisting progress to run.ckpt:
xcrack --checkpoint run.ckpt --pattern big-mask.txt --no-default-list vault.pdf

# If the process is killed, just run the SAME command again — it resumes near
# where it stopped and prints e.g. "resuming from candidate 4300000 (checkpoint run.ckpt)".
```

How it works: the candidate position is written to `FILE` every 100 000
candidates (atomically, with a signature of the target and candidate set). On a
re-run with a matching signature, iteration resumes a safety margin *behind* the
last saved position, so no candidate that was handed out but not yet verified
before the interruption is skipped. When the search finishes (password found or
keyspace exhausted) the checkpoint file is removed, so the next run starts fresh.
Changing the target or the candidate set changes the signature and starts over.

`--checkpoint` requires **exactly one** source (it tracks a single global
cursor) and is meant for a single encrypted target; the candidate source must be
deterministic (masks, wordlists, chains — not `stdin`).

### Output

| Flag | Meaning |
| ---- | ------- |
| `--format text\|json\|jsonl` | result rendering (default `text`) |
| `-o`, `--out DIR` | write the decrypted tree under `DIR/<name>.extracted/` + a `manifest.json` |
| `--extract-suffix S` | change the per-source directory suffix (default `.extracted`; `''` = the bare source name). Must be a single path segment (no `/` or `..`) |
| `--results-file FILE` | append a JSON manifest per input to `FILE` |
| `--outfile-format LIST` | emit found-password lines to `--results-file`/stdout in a field format: comma list of `1`=target, `2`=plain, `3`=hex-plain (e.g. `1,2`), joined by `:` (hashcat-style) |
| `--reuse-output` | with `-o`: skip any source whose extracted output is already present and still valid (same content + candidate set), recorded per-output in `.xcrack-stamp` — a repeat extraction becomes near-instant (unlike `--found-cache`, which still re-verifies and re-extracts). `--session FILE` similarly skips searched files but keeps no `-o` output |
| `--progress` | print live progress to stderr: files done/total, candidates, rate, elapsed, ETA |
| `--status-timer N` | print a files-done/elapsed heartbeat to stderr every `N` seconds (independent of `--progress`) |
| `--log-level LEVEL` | `debug\|info\|warn\|error` structured logging to stderr (never logs secrets) |
| `--show-config` | print the effective configuration (flags + env + config file + defaults, merged) and exit — no cracking |
| `--show-cache` | list the passwords held in the found-password cache / potfile and exit (needs `--found-cache`/`--remember`/`--potfile`) |

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

# Change the per-source directory suffix (e.g. to integrate with another tool):
xcrack -p hunter2 -o ./out --extract-suffix .unpacked archive.zip
#   -> ./out/archive.zip.unpacked/...

# Print the exact effective settings before committing to a long run:
xcrack --show-config -w rockyou.txt --pattern best64.rule archive.zip
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
| `--time-limit D` | give up on a file after `D` with no success and move on (per-file; a clear alias of `--timeout`). A file that hits the limit is reported *locked* (exit 1), never an error, so one stuck file never fails a batch |
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
  context_candidates: false
  hint_candidates: false    # derive guesses from an embedded password hint
  hint_rules:               # hashcat-style rules applied to hint-derived words
    - "c"
    - "$2 $0 $2 $4"
  spray: true               # curated spray set (common + season/year patterns)
  spray_tokens: [Acme]      # org/product/user tokens mangled into the spray set
  adaptive: true            # corpus-wide promotion across files (smallest first)

candidates:
  passwords: [infected, Welcome1]
  wordlists: [rockyou.txt, corp-words.txt.gz]
  breach: [leaked-passwords.txt.gz]  # frequency-annotated breach corpora
  breach_min_count: 10               # drop entries seen fewer than N times
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

Ready-to-adapt example configs live in [`config/`](../config/) — basic wordlist,
mask+rules, hint+context, fast triage, and deep batch — see its
[`README`](../config/README.md).

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

# --- LibreOffice / OpenOffice (ODF: .odt/.ods/.odp; AES-256 CBC or GCM) ---
xcrack -p hunter2 notes.odt

# --- KeePass database (.kdbx, KDBX4: Argon2d/Argon2id/AES-KDF) ---
xcrack -w rockyou.txt secrets.kdbx    # recovers the master passphrase

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

### `hashline`

Emit a crackable hash line for an external GPU cracker instead of searching
in-process — Xcrack probes the file once and prints the `$…$` string that
hashcat (`-m <mode>`) or John the Ripper (`--format=<name>`) expects. The hash
line goes to **stdout** (so it pipes cleanly into a cracker); a
`# <file> (hashcat -m N | john --format=X)` note goes to stderr.

Supported today:

| Scheme | Line | hashcat `-m` | John `--format=` |
| --- | --- | --- | --- |
| OOXML Office (agile + standard) | `$office$` | 9400 / 9500 / 9600 | `office` |
| PDF (RC4 / AESV2 / AESV3) | `$pdf$` | 10400 / 10500 / 10600 / 10700 | `PDF` |
| WinZip AES ZIP entries (per entry) | `$zip2$` | 13600 | `ZIP` |

These emitters are cross-validated against real hashcat (see
`scripts/hashcat-xval.sh`). Other schemes report that no emitter exists yet.
For a ZIP, a `$zip2$` line is emitted per WinZip-AES entry (AES-128/192/256);
ZipCrypto entries are not exported here — they are attacked by the built-in
known-plaintext path instead. Note the `$zip2$` line embeds the entry's full
ciphertext and authentication tag, which the lightweight probe-time report
omits, so `hashline` re-reads the entry to build it.

```sh
xcrack hashline secret.docx > hashes.txt         # $office$*2013*100000*256*...
xcrack hashline *.pdf 2>/dev/null >> hashes.txt  # append $pdf$ lines
xcrack hashline archive.zip 2>/dev/null >> hashes.txt  # $zip2$ per AES entry
hashcat -m 9600 hashes.txt rockyou.txt           # crack on the GPU box
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

**Hybrid (wordlist ± mask).** `--hybrid-append MASK` tries `word + maskExpansion`
for every wordlist word (hashcat's dict+mask, `-a 6`); `--hybrid-prepend MASK`
tries `maskExpansion + word` (mask+dict, `-a 7`). Both are repeatable and share
the run's custom charsets.

```sh
# "Sesame" + two digits (Sesame00..Sesame99), for every word in names.txt:
xcrack -w names.txt --hybrid-append '?d?d' vault.7z

# a leading symbol in front of each word:
xcrack -w names.txt --hybrid-prepend '?s' vault.7z
```

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

- **`Options.ContextCandidates`** — the library form of `--context`: seed each
  search with name- and sibling-text-derived guesses. For a whole-file-encrypted
  input (an encrypted PDF/OOXML/age/…) the top-level file name isn't known to the
  engine, so prepend it yourself with `candidates.FromName(filepath.Base(path))`.
- **`Options.FastReject`** — a cheap pre-KDF filter to prune a hopeless keyspace
  using a domain constraint, without a false-positive risk (it is never applied
  to passwords promoted from an outer layer):

  ```go
  pool := xcrack.NewPool(xcrack.Options{
      // This appliance only ever sees 6-digit numeric PINs: skip everything else
      // before the expensive KDF runs.
      FastReject: func(path string, cand []byte) bool {
          if len(cand) != 6 { return true }
          for _, c := range cand { if c < '0' || c > '9' { return true } }
          return false
      },
  })
  ```

- **`pool.Metrics()`** — aggregate counters (files, candidates tried, bytes,
  nodes by status, durations) for telemetry; carries no secrets.

Candidate sources live in `github.com/rom/xcrypto/candidates`: `Explicit`,
`Bytes`, `File` (gzip-aware), `Stdin`, `DefaultList`, `Chain`, `ByScore`
(+ a `Markov` model) to order a wordlist's head by likelihood, `Combinator`,
`Dedup`, `MarkovGen`, and the context helpers `FromName` / `FromText` / `Context`.

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
| `-gpu` | off | enable the optional OpenCL GPU tier (needs a `-tags opencl` build + OpenCL hardware; otherwise logs why and runs on CPU) |
| `-gpu-selftest` | off | validate the OpenCL PBKDF2 kernel against the CPU reference, then exit |

**Optional GPU tier (server only).** The default `xcrackd` is pure-Go and
CPU-only. On a server with OpenCL hardware you can build an accelerated binary
and opt in:

```sh
go build -tags opencl -o bin/xcrackd-gpu ./xcrack/cmd/xcrackd
bin/xcrackd-gpu -gpu-selftest        # prove the kernel matches the CPU reference
bin/xcrackd-gpu -gpu -addr :8080     # hardware-gated; falls back to CPU if absent
```

When a device is present and the kernel passes its self-test, `--gpu` wires the
accelerator straight into the **live crack loop**: for acceleration-capable
targets (WinZip-AES ZIP entries, encrypted DMG, and other PBKDF2-HMAC-SHA1
schemes) the keyspace sweep is derived on the device in batches, and the CPU
verifier re-checks every candidate the device flags. Promoted / hint / context
passwords are still tried on the CPU first, and any unsupported parameter or
device error falls back transparently to the pure-Go CPU search — so the GPU
only ever changes speed, never results.

The GPU tier only accelerates PBKDF2-HMAC-SHA1 key derivation (the shared KDF);
it never parses or opens file content, never decides a match on its own, and the
default build / CI never include it (ADR 0001 amendment).

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

From the command line, without writing any Go:

```sh
# Probe a file and print its challenge envelope(s) for an external cracker:
xcrack export-challenge invoice.docx > invoice.challenge.json

# ... crack it elsewhere, producing a recovered-password envelope, then resume:
xcrack --resume-from invoice.recovered.json invoice.docx   # tries the password first
```

A recovered-password envelope is just
`{"xcrack_recovered_version":1,"password":"..."}`; `--resume-from` accepts one
object or a JSON array and is repeatable.

---

## Distributed cracking across servers

For a hard password, run many `xcrackd` workers (each optionally GPU-accelerated)
and let `xcrack` coordinate. It probes and assembles candidates locally and
streams disjoint batches of the keyspace to the fleet.

```sh
# Collective: every server attacks the SAME file on disjoint batches; first hit wins.
xcrack --server http://gpu1:8080 --server http://gpu2:8080 \
       -w rockyou.txt --cluster-mode collective secret.docx

# Partition: server groups take DIFFERENT files, cracked in parallel.
xcrack --server http://a:8080@g1 --server http://b:8080@g1 \
       --server http://c:8080@g2 --server http://d:8080@g2 \
       --cluster-mode partition -w rockyou.txt *.docx
```

Flags: `--server URL[@GROUP]` (repeatable), `--cluster-mode collective|partition`,
`--cluster-batch N` (candidates per request, default 20000),
`--cluster-allow-defaults` (let each server also try its own default list),
`--cluster-per-request D` (per-request server deadline hint). The same set is
configurable under a `cluster:` block (servers, mode, batch, allow_defaults,
per_request). Every attack type works — the coordinator pulls from the usual
candidate builder and ships batches — and a worker can only ever confirm a
candidate it was handed, so it cannot cause a false positive. Each server must
run `xcrackd` (behind your own authn/TLS); point it at a GPU build (`-gpu`) for
the real speed-up.

---

## Inspect, benchmark, estimate

Four modes that don't crack — they tell you what a run *would* do, so you can
plan an attack (or a recovery queue) before committing hours to it.

```sh
# Print the exact candidate stream a set of flags would try (hashcat --stdout):
xcrack --stdout -w rockyou.txt --prince --limit 50     # first 50, no file needed

# How big is the keyspace?  (masks/lists report instantly; wordlists are counted)
xcrack --keyspace --pattern masks.txt
xcrack --keyspace -w rockyou.txt

# How fast can THIS file's format be verified? (candidates/sec, hashcat -b)
xcrack --benchmark secret.docx
xcrack -b secret.docx secret.pdf archive.zip

# Put the two together: keyspace x rate -> time to crack this file.
xcrack --estimate --pattern masks.txt secret.docx
#   secret.docx  [office-agile]
#       rate      1.09k candidates/sec
#       keyspace  1000000
#       time      ~15m19s to exhaust, ~7m40s expected to a hit
```

`--benchmark`/`--estimate` probe the file's real verifier (so the rate reflects
the actual KDF cost — a RAR5 or Office-2013 file is far slower than WinZip-AES),
which is exactly the per-format speed the recovery-queue workflow needs to order
jobs. `--stdout`/`--keyspace` don't need a source file; `--limit N` bounds them.
During a real crack, `--progress` shows a true percent + ETA when the target's
keyspace is known (e.g. a mask).

---

## ZipCrypto known-plaintext attack

Traditional PKWARE ("ZipCrypto") encryption is cryptographically broken: given
~12+ bytes of known plaintext for an entry and the matching ciphertext, its
internal key state can be recovered with **no password** (Biham–Kocher). The
`xcrypto/scheme/zipcrypto` package implements the full attack in pure Go:

```go
import "github.com/rom/xcrypto/scheme/zipcrypto"

// plain and cipher are the known plaintext and ciphertext at the same stream
// positions (e.g. a file you know is in the archive). keys is the internal state.
keys, ok := zipcrypto.RecoverKeys(plain, cipher)
if ok {
    // Roll back across the 12-byte header (recovering it) to reach the entry start,
    // then decrypt the whole entry with keys.Decrypt.
    start, _ := keys.RollBack(headerCiphertext)
    _ = start
}
```

**This is compute-heavy.** The keystream leaves a few ×10⁵ internal-key
candidates and each needs a ~2¹⁶ key1 enumeration (a two-step *fiber* roll-back
keeps it there rather than fanning out 256-wide per level — a ~34× per-window
speedup). The candidates are independent, so the search runs across all CPU cores
and scales **near-linearly** — measured ~16 / 28 / 62 candidates·s⁻¹ on 1 / 2 / 4
cores. A representative full recovery (54-byte known plaintext) examined ~185k
candidates and recovered the keys in **~57 min on a 4-core box**; expect roughly
an hour on a laptop, a few minutes on a many-core server, and a further small
constant factor from dedicated C++ tools such as *bkcrack*. More known plaintext
does not shrink the candidate set. Use `RecoverKeysBudget(plain, cipher,
maxCandidates)` to bound the effort and resume with a larger budget, hand the
problem to a local *bkcrack* binary with `RecoverKeysWith(plain, cipher,
zipcrypto.ExternalBkcrack{Bin: "bkcrack"})` (CLI `--bkcrack /path/to/bkcrack`),
or offload the heavy search to an external/GPU engine via the challenge-export
bridge above. The offload and this package's ZipCrypto primitives are
cross-validated against the real *bkcrack* binary (`TestExternalBkcrackReal`,
run with `XCRACK_BKCRACK=/path/to/bkcrack`); the offload's answer is always
re-validated locally, so an external engine can never cause a false positive.

`xcrack kp` exposes all of this: `--plain`/`--cipher` are the aligned known
plaintext and ciphertext, `--bkcrack` offloads the search, and `--decrypt ENTRY
--offset N` recovers the keys then decrypts a whole ZipCrypto entry — rolling the
state back over the 12-byte header and any earlier data so a *mid-entry* known
plaintext still unlocks the entire entry (`--keep-header` keeps the header
bytes). `--recover-password MAXLEN:CHARSET` then recovers the actual password
from the entry-start state via bkcrack (re-validated locally). The engine can do
the same automatically for an archive entry via `Options.KnownPlaintext{For,
Offload}` (e.g. a STORED entry whose content an embedder already holds).

Because every entry in a ZipCrypto archive shares one password-derived
pre-header key state, that single recovery unlocks the *whole* archive. Add
`--zip ARCHIVE` to a `--decrypt` run and `kp` seeds the recovered entry-start
state into every other entry and decrypts them all with no further search —
`--zip-out DIR` writes the decrypted files, otherwise it lists what decrypts.
Each entry is independently CRC-re-validated (so a wrong state decrypts nothing),
and WinZip-AES / non-ZipCrypto entries are skipped.

The 40-bit **PDF** RC4 schemes have the same password-independent key
bottleneck as legacy Office: `xcrack pdf-keyattack FILE` sweeps the 2^40 file-key
space against the `/U` verifier and recovers the key for a V1/R2 (or 40-bit
R3/R4) PDF with no password, shardable with `--shard i/N` and parallel over
`--workers`. `--gpu` offloads the sweep to an OpenCL device in a `-tags opencl`
build (every hit re-checked on the CPU; falls back to CPU otherwise), exactly as
`office-keyattack --gpu` does for the Office 97/2000 trunc sweep. 128-bit RC4 and
the AES PDF schemes have no such shortcut and the command declines them.

**Microsoft Access** goes further still: a Jet (`.mdb`, Access 97–2003) database
stores its password merely XOR-obfuscated in the header, so there is nothing to
crack at all. `xcrack access-recover FILE` de-obfuscates it (the fixed header
mask, and on Jet4 a second mask folded from the creation date) and prints the
password directly. ACE (`.accdb`, Access 2007+) uses a real Office-style KDF with
no shortcut and is reported as needing a password search. The Jet decode is
cross-validated against jackcess, an independent implementation.

Two further knobs: the compute-heavy in-process attack honors context
cancellation (`RecoverKeysCtx`), so an embedder can bound it; and *sparse* known
plaintext (scattered known bytes) is available through the offload by passing
bkcrack's `-x <offset> <hex>` via `ExternalBkcrack.Args` (the in-process attack
is contiguous-only). Recovering a running key state from a broken cipher is
legitimate cryptanalysis — no sound cipher is weakened.

---

## Supported formats

| Family | Formats | Notes |
| ------ | ------- | ----- |
| Archives | ZIP (ZipCrypto, WinZip AES), tar, gzip, bzip2, xz, **7z**, **RAR** | 7z/RAR also **header-encrypted** (`-mhe` / `-hp`) |
| MS Office | OOXML (`.docx/.xlsx/.pptx`, agile + standard), legacy (`.doc/.xls/.ppt`: RC4 CryptoAPI / RC4 97-2000 / XOR) | legacy XOR body reconstruction: Excel only |
| Other docs | PDF (RC4 / AESV2 / AESV3, user + owner), ODF (AES-256-CBC), **Apple iWork** (Pages/Numbers/Keynote, '13+ `.iwpv2`) | iWork recovers the passphrase only (body not reconstructed) |
| Mail / passphrase | MIME (`.eml`) attachments, **age** (scrypt), **symmetric OpenPGP** (`gpg -c`) | |
| Keys / key stores | **OpenSSH** private keys, **PEM/PKCS#8** (PBES2 + DEK-Info), **JKS**, **PKCS#12** (`.p12/.pfx`), **PuTTY** `.ppk` (v3/v2), **SQLCipher** (library-only) | |

Not yet implemented (staged): KeePass (needs in-tree Argon2d), encrypted DMG,
ODF AES-GCM, and legacy-Office macro/VBA auxiliary-stream decryption. Out of
scope: GPU cracking in-tree, any online/network attack, and public-key PDF
(needs a private key, not a password). See the [roadmap](roadmap.md).
