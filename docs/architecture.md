# Xcrack — Architecture

Status: Draft · Audience: engineers integrating or extending Xcrack ·
Style: C4 (Context → Containers → Components) plus key runtime views.

## 1. Purpose & context

Xcrack makes password-protected and encrypted files readable so their content
can be analysed. Its dominant deployment is **embedded inside Impex**, a
malicious-content scanner: Impex cannot inspect a file it cannot read, and
attackers routinely ship payloads inside password-protected archives and Office
documents (with the password in the email body) specifically to blind scanners.
Xcrack removes that blindfold by decrypting and recursively unpacking the file
into its real, analysable content.

A secondary deployment is the **`xcrack` CLI** for manual triage, DFIR, and
recovery of one's own files.

### 1.1 System context (C4 level 1)

```
                         password candidates
                    (email body, wordlists, patterns)
                                  │
                                  ▼
  ┌──────────┐   file bytes   ┌───────────────┐   decrypted content tree   ┌──────────────┐
  │  Impex   │ ─────────────▶ │    Xcrack     │ ─────────────────────────▶ │ Impex scanner│
  │ scanner  │                │  (embedded)   │   + recovered passwords    │  / analysts  │
  └──────────┘ ◀───────────── └───────────────┘                            └──────────────┘
                 result tree          │
                                       │ uses
                                       ▼
                               ┌───────────────┐
                               │ Xfileformats  │  detect · probe · verify
                               │  (library)    │  decrypt · unpack
                               └───────────────┘
```

External actors and systems:

- **Impex scanner** — the primary caller. Hands Xcrack untrusted file bytes and
  a set of candidate passwords; receives a tree of decrypted/extracted content
  plus the passwords that worked.
- **Operator / analyst** — uses the CLI for the same capability interactively.
- **Candidate sources** — wordlists, explicit passwords, pattern/rule files, and
  passwords harvested by Impex (e.g. from an email body) and injected per scan.

### 1.2 Key quality drivers

Driven by the [ASR](asr.md); summarised here because they shape every view:

- **Safety under hostile input** — the input is assumed malicious. No panics
  escape, no code executes, resource use is strictly bounded (bomb-resistant).
- **Embeddability** — clean Go API, no global state, no external processes, no
  network, `context`-driven cancellation, predictable resource ceilings.
- **Reusability** — format knowledge lives in a standalone, policy-free library
  (**Xfileformats**) any tool can import.
- **Throughput at scale** — Impex scans many files; concurrency is tunable along
  two axes and shares a bounded pool.
- **Correctness** — a reported "decrypted" result is verified, not guessed.

## 2. Containers (C4 level 2)

Three deployable/importable units across two Go modules:

```
┌───────────────────────────── module: github.com/rom/xcrack ─────────────────────────────┐
│                                                                                          │
│   ┌────────────────────┐         ┌──────────────────────────────────────────────┐       │
│   │   cmd/xcrack (CLI)  │ ──────▶ │              pkg/xcrack (Engine)             │       │
│   │  flag parsing,      │  opts   │  CandidateSource · PatternEngine · Pool/     │       │
│   │  config load,       │         │  Scheduler · Decomposer (recursion) ·        │       │
│   │  output rendering   │ ◀────── │  Budget/Limits · Result tree · Reporter      │       │
│   └────────────────────┘ result  └──────────────────────────────────────────────┘       │
│                                             │ imports                                     │
└─────────────────────────────────────────────┼────────────────────────────────────────────┘
                                              ▼
┌────────────────────── module: github.com/rom/xfileformats ───────────────────────────────┐
│   Registry · Detector · Format plugins (Encrypted / Container / Explodable) ·             │
│   Probe→Challenge · Verify · Decrypt · Entries   —   policy-free, reusable                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 Xfileformats (`github.com/rom/xfileformats`)

The standalone library. It answers, for a single byte stream, questions that any
tool might ask — with **no notion** of candidate lists, search strategy,
concurrency, or recursion policy (those belong to the caller):

- *What format is this?* → `Detect`
- *Is it encrypted, and with what parameters?* → `Probe` → `Challenge`
- *Does this one password work?* → `Verify`
- *Decrypt it with the derived key* → `Decrypt`
- *Is it a container, and what's inside?* → `Entries`

Because it never opens documents semantically (it only derives keys and moves
bytes), it cannot execute macros or trigger document exploits — a safety
property, not just a packaging one (see [ADR-0001](adr/0001-pure-go-no-external-binaries.md)).

### 2.2 Engine (`github.com/rom/xcrack`, `pkg/xcrack`)

What Impex embeds. It owns everything *policy*:

- **CandidateSource** — unifies explicit passwords, wordlists, built-in default
  list, and generated candidates into one iterable stream (de-duplicated,
  ordered, bounded).
- **PatternEngine** — expands masks and applies mangling rules (hashcat-compatible).
- **Scheduler / Pool** — the two-axis concurrency model and the reusable, bounded
  worker pool a long-running Impex service constructs once.
- **Decomposer** — the recursive algorithm: detect → decrypt → unpack → recurse,
  producing the result tree, enforcing budgets, and doing password promotion.
- **Reporter** — renders results (tree + manifest) and recovered passwords.

### 2.3 CLI (`github.com/rom/xcrack`, `cmd/xcrack`)

A thin shell over the engine: parse flags and config, build `Options`, stream
sources in, render output. It adds no capability the library lacks (full
library/CLI parity is a requirement — see [ASR](asr.md) CON-3).

## 3. Components (C4 level 3)

### 3.1 Xfileformats components

```
xfileformats/
├─ registry.go        Register(Format) + detection dispatch
├─ format.go          Format, Encrypted, Container, Explodable interfaces; Caps
├─ challenge.go       Challenge type (KDF params, salt, verifier, cipher spec)
├─ detect.go          magic-byte sniffing, bounded peek
├─ limits.go          reader guards reused by formats (bounded ReaderAt, ratios)
├─ formats/
│   ├─ zipcrypto/     legacy ZIP + WinZip AES
│   ├─ ooxml/         MS Office agile + standard encryption
│   ├─ pdf/           RC4 40/128, AESV2-128, AESV3-256 (user + owner pw)
│   ├─ msoffice/      legacy .doc/.xls/.ppt (CryptoAPI/RC4)
│   ├─ odf/           ODF (Blowfish-CFB legacy, AES-GCM modern)
│   └─ archive/       tar, gzip, bzip2, xz/lzma, 7z, rar, eml/MIME  (unpack-only)
└─ internal/crypto/   shared KDF/cipher helpers (PBKDF2, AES-CBC/GCM, RC4, ...)
```

Each format advertises its capabilities via `Caps{Encrypted, Container,
Explodable}`. A format may be both (an encrypted ZIP is `Encrypted` + `Container`).

### 3.2 Engine components

```
pkg/xcrack/
├─ engine.go          Engine, Options, Pool; the public embed surface
├─ decompose.go       recursive walk, node tree, password promotion
├─ node.go            Node, Result, per-node status/error
├─ budget.go          Budget + Limits accounting (depth, bytes, nodes, ratio, time)
├─ candidates/        CandidateSource, wordlist/file/stdin/default readers, dedup
├─ patterns/          mask expander + rule engine (hashcat-compatible) + YAML wrapper
├─ sched/             two-axis scheduler, bounded semaphore, throttle
├─ report/            text / json / jsonl renderers, manifest, redaction
└─ store/             intermediate materialisation (memory → spill temp)
```

## 4. Runtime views

### 4.1 Single-file decryption (the hot path)

```
Engine.Process(file, candidates)
  │
  ├─ xfileformats.Detect(peek)                → format (or "plaintext leaf")
  ├─ if Encrypted:
  │     ch := fmt.Probe(file)                 → Challenge (salt, verifier, KDF)
  │     for cand in candidates (bounded):     ── fan out to `workers` goroutines
  │         ok, key := fmt.Verify(ch, cand)   ── the expensive KDF step
  │         if ok: record password; break (stop-on-first)
  │     plain := fmt.Decrypt(file, key)
  │  else:
  │     plain := file
  ├─ if Container (and within limits):
  │     for entry in fmt.Entries(plain):      → recurse Engine.Process(entry, candidates')
  │  else:
  │     emit leaf(plain)                       → content handed back
  └─ assemble Node{password, content, children, status}
```

The candidate loop is the only CPU-heavy part (KDFs are deliberately slow), so
that is where intra-file parallelism (`--workers`) is applied.

### 4.2 Recursive decomposition (nesting)

A file becomes a **tree**. Example — a malicious invoice:

```
invoice.zip            [container, encrypted]   password = "infected"
├─ report.docx         [encrypted document]     password = "Welcome1"   → leaf (handed back)
└─ bundle.7z           [container]               (no password)
   ├─ dropper.scr       → leaf (handed back)
   └─ readme.txt        → leaf (handed back)
```

Decomposition rules:

- Each new layer is re-detected from scratch (never trust the extension).
- **Password promotion:** a password that unlocked an ancestor is tried first on
  descendants; promoted passwords also seed the pattern engine for inner layers.
- **Documents are leaves by default** — a decrypted `.docx` is handed back whole;
  it is only exploded into its internal parts when `--explode-documents` / the
  library `Options.ExplodeDocuments` is set. See
  [ADR-0007](adr/0007-documents-as-leaves.md).
- Every descent checks the **budget** (depth, cumulative bytes, node count,
  per-entry ratio) and **cycle detection** by content hash; a breach prunes that
  branch and is recorded — it never aborts the whole scan (see `--keep-going`).

### 4.3 Batch scanning & concurrency

Two orthogonal axes, bounded by one global semaphore so resource use stays
predictable inside Impex (see [ADR-0006](adr/0006-concurrency-model.md)):

```
          ┌── file-jobs (N files concurrently) ──┐
 input ──▶ │  fileⁱ ─▶ workers (M candidate       │ ──▶ results
 list      │           testers within the file)   │
          └──────────────────────────────────────┘
   effective concurrency = file-jobs × workers  ≤  max-procs  (global cap)
```

A long-running Impex service constructs one `Pool` with a fixed budget and feeds
a stream of files through it, rather than spinning up goroutines per call.

## 5. Deployment / embedding view

- **In Impex (primary):** Impex imports `pkg/xcrack`, builds a `Pool` at startup
  with a fixed `Options{Workers, FileConcurrency, Budget, Limits}`, and calls
  `pool.Process(ctx, reader, candidates)` per file. Decrypted content is returned
  as streams (no plaintext written to disk unless the caller asks). `context`
  deadlines enforce the scanner's per-file SLA.
- **CLI (secondary):** `xcrack --source ... --out ... --wordlist ...` for
  interactive use; identical engine underneath.
- **No external processes, no network, no privileged access.** A single static
  binary / a pure-Go dependency.

## 6. Cross-cutting concerns

| Concern | Approach |
| ------- | -------- |
| **Safety** | Assume-hostile input; bounded readers; strict budgets; panic-to-error recovery at every format boundary; never execute content. See [threat model](threat-model.md). |
| **Cancellation** | `context.Context` threaded through engine, scheduler, and every long loop (per-file timeout + whole-run deadline). |
| **Observability** | Structured logging with password redaction by default; progress callbacks (`OnProgress`, `OnFound`); optional audit log for DFIR. |
| **Secret hygiene** | Recovered passwords never logged at default level; emitted only to the result/results-file; redacted in errors. |
| **Determinism** | Candidate ordering and traversal order are deterministic given the same inputs, to make scans reproducible. |
| **Extensibility** | New formats = new `Format` plugin registered in Xfileformats; the engine needs no change. |

## 7. Key architectural decisions

See the [ADR index](README.md#architecture-decision-records). The load-bearing
ones: pure Go / no external binaries ([0001](adr/0001-pure-go-no-external-binaries.md)),
the standalone Xfileformats split ([0002](adr/0002-standalone-xfileformats-library.md)),
recursive decomposition ([0003](adr/0003-recursive-decomposition-model.md)), and
the hostile-input budget model ([0004](adr/0004-hostile-input-safety-budgets.md)).
