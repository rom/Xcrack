# Xcrack — Detailed Design

Status: Draft. This document specifies the public APIs of **Xfileformats** and
the **Xcrack engine**, the recursive decomposition algorithm, the candidate /
pattern engine, the concurrency model, the configuration and output handling,
and the error model. Signatures are indicative (pre-implementation) and will be
finalised against Go 1.25+ (stdlib crypto/pbkdf2 requires 1.24).

---

## 1. Xfileformats — the standalone library API

Design goal: a tool that imports Xfileformats can answer "what is this file, is
it encrypted, unlock it with *this* password, and list what's inside" **without
pulling in any cracking policy**. No globals beyond an optional default
registry; everything is injectable.

### 1.1 Capabilities & format interface

```go
package xfileformats

type Caps struct {
    Encrypted  bool // password-protected; implements Encrypted
    Container  bool // holds child entries; implements Container
    Explodable bool // a document that *can* be decomposed into parts on request
}

type Format interface {
    // Name is a stable identifier, e.g. "ooxml", "pdf", "zip".
    Name() string
    // Detect sniffs a bounded peek of the stream head. Returns a confidence in
    // [0,1] and whether this format claims the stream. Must not read beyond peek.
    Detect(peek []byte) (confidence float64, ok bool)
    Caps() Caps
}
```

Formats additionally implement one or both behavioural interfaces:

```go
// Encrypted is implemented by password-protected formats.
type Encrypted interface {
    // Probe extracts the verifiable crypto material ONCE, so the caller can test
    // many candidates cheaply without re-parsing. Must be cheap and allocation-bounded.
    Probe(r io.ReaderAt, size int64) (*Challenge, error)

    // Verify tests a single password against a probed Challenge. It performs the
    // (deliberately expensive) KDF and verifier check. On success it returns the
    // derived content key so Decrypt need not re-derive it.
    Verify(ch *Challenge, password []byte) (ok bool, key []byte, err error)

    // Decrypt streams plaintext given the derived key (or password, if no key).
    // The returned reader is bounded by DecryptedSizeHint when known.
    Decrypt(r io.ReaderAt, size int64, ch *Challenge, key []byte) (io.Reader, error)
}

// Container is implemented by archives and compound documents.
type Container interface {
    // Entries lists child entries without extracting them. Each Entry.Open()
    // returns a bounded reader over that entry's (still possibly encrypted) bytes.
    Entries(r io.ReaderAt, size int64) ([]Entry, error)
}

type Entry struct {
    Path             string // path within the container (normalised, no traversal)
    Size             int64  // declared uncompressed size (untrusted; cross-checked)
    CompressedSize   int64
    Open             func() (io.Reader, error)
    Encrypted        bool   // some containers encrypt per-entry (e.g. ZIP)
}
```

### 1.2 Challenge

The `Challenge` is the small, serialisable description of what it takes to test
a password — the heart of "probe once, test many":

```go
type Challenge struct {
    Format     string            // owning format name
    KDF        KDFSpec           // algorithm + params (iterations, salt, memory, ...)
    Cipher     CipherSpec        // algorithm, mode, key/iv sizes
    Verifier   []byte            // encrypted verifier / hash used to confirm a password
    VerifierIV []byte
    Extra      map[string][]byte // format-specific fields (owner-key data, etc.)
    DecryptedSizeHint int64      // -1 if unknown
}
```

`Challenge` is designed to be marshallable (it is effectively the same
information John the Ripper's `*2john` tools emit), so a caller could extract
challenges in one process and test them in another.

### 1.3 Detection & registry

```go
type Registry struct { /* ... */ }

func NewRegistry() *Registry
func (r *Registry) Register(f Format)
func (r *Registry) Detect(peek []byte) (Format, error) // best-confidence match

// A default registry is populated by the formats/* packages via their
// Register(reg) constructors. Callers that want determinism/isolation build
// their own Registry and register only the formats they trust.
func Default() *Registry
```

Formats are registered **explicitly** by constructor (`zipcrypto.Register(reg)`)
rather than by `init()` side effects, so a consumer controls exactly which
formats — and thus which parsers exposed to hostile input — are enabled. See
[ADR-0002](adr/0002-standalone-xfileformats-library.md).

### 1.4 What the library deliberately does NOT do

- No candidate generation, wordlists, masks, or rules.
- No concurrency or worker pools.
- No recursion/traversal policy (it lists one container's entries; it does not
  walk the tree).
- No file-system or network I/O beyond the `io.ReaderAt` it is handed.
- No document semantics (never executes macros, resolves references, renders).

---

## 2. Xcrack engine API — what Impex embeds

```go
package xcrack

// Options configures a run. Every CLI flag maps to a field here (CLI/library parity).
type Options struct {
    // concurrency
    Workers         int           // candidate-test goroutines within one file (0 => NumCPU)
    FileConcurrency int           // files processed concurrently (0 => NumCPU for batch)
    MaxProcs        int           // global ceiling; file-jobs*workers bounded by this

    // search behaviour
    NoRecurse        bool         // disable container decomposition (default: recurse)
    NoPromote        bool         // disable password promotion (default: promote ancestors first)

    // recursion / documents
    FindAll          bool         // keep searching after first match (reserved; default stop-on-first)
    ExplodeDocuments bool         // decompose documents into parts (default false, opt-in)

    // budgets & limits (hostile-input safety)
    Limits  Limits
    Budget  Budget                // per-file and whole-run time budgets

    // formats
    Registry *xfileformats.Registry // which formats are enabled (nil => a safe default set)

    // callbacks
    OnProgress func(Progress)
    OnFound    func(Found)        // a password unlocked a node

    Logger   Logger               // structured, redacting logger (nil => no-op)
}

type Limits struct {
    MaxDepth        int   // nesting ceiling (default 32)
    MaxTotalBytes   int64 // cumulative decompressed budget across the whole tree
    MaxNodes        int   // total extracted entries
    MaxEntrySize    int64 // single-entry cap
    MaxRatio        int   // per-entry compression-ratio cap (bomb guard)
    MaxCandidates   int64 // cap candidates tested per file (0 => unlimited)
    SpillThreshold  int64 // above this, intermediates spill to temp instead of memory
    TempDir         string
}

type Budget struct {
    PerFile time.Duration // 0 => none
    Total   time.Duration // whole-run deadline (also honoured via ctx)
}
```

### 2.1 The two entry shapes

```go
// One-shot: construct, process, discard. Convenient for the CLI and simple callers.
func Process(ctx context.Context, src io.ReaderAt, size int64,
             candidates CandidateSource, opts Options) (*Result, error)

// Long-running: a reusable, bounded pool a service constructs ONCE and feeds.
// This is the shape Impex uses.
type Pool struct { /* ... */ }
func NewPool(opts Options) (*Pool, error)
func (p *Pool) Process(ctx context.Context, src io.ReaderAt, size int64,
                       candidates CandidateSource) (*Result, error)
func (p *Pool) Close() error
```

`Pool` holds the global worker semaphore and reusable buffers; `Process` is safe
for concurrent use so Impex can call it from many request goroutines while the
pool enforces the global ceiling.

### 2.2 Result model (both password and content, per node)

```go
type Result struct {
    Root    *Node
    Stats   Stats   // files seen, candidates tested, bytes extracted, elapsed, limit hits
}

type Node struct {
    Path        string          // lineage, e.g. "invoice.zip!/report.docx"
    Format      string          // detected format ("" if plaintext/unknown leaf)
    WasEncrypted bool
    Password    string          // the candidate that unlocked this node ("" if none)
    Status      NodeStatus      // Decrypted | Plain | Locked | LimitExceeded | Error
    Err         error           // non-nil for the Error status; never a panic
    Content     ContentRef      // how to read this node's (decrypted) bytes
    Children    []*Node         // container entries, recursively
}

type NodeStatus int
const (
    StatusPlain NodeStatus = iota // not encrypted, not a container boundary of interest
    StatusDecrypted               // was encrypted, a candidate worked
    StatusLocked                  // encrypted, no candidate worked within budget
    StatusLimitExceeded           // pruned by a limit (depth/bytes/nodes/ratio/cycle)
    StatusError                   // a recoverable per-node error
)

// ContentRef avoids forcing everything into memory: it yields a reader on demand,
// backed by memory under SpillThreshold or a locked temp file above it.
type ContentRef interface {
    Open() (io.ReadCloser, error)
    Size() int64
    SHA256() [32]byte
}
```

A `StatusLocked` or `StatusError` node does **not** sink the scan: siblings and
the rest of the tree still process (`--keep-going`), and the node is reported so
Impex can quarantine/flag the still-encrypted content.

### 2.3 Callbacks

```go
type Progress struct {
    Path            string
    CandidatesTried int64
    Rate            float64 // candidates/sec
    Depth           int
    BytesExtracted  int64
}
type Found struct {
    Path     string
    Format   string
    Password string // delivered to the caller; redacted from logs
}
```

---

## 3. Candidate / pattern engine

### 3.1 CandidateSource

```go
package xcrack

type CandidateSource interface {
    // Next yields the next candidate, or io.EOF. Implementations are NOT required
    // to be thread-safe; the scheduler wraps one in a synchronised, batching feeder.
    Next() ([]byte, error)
    // Len returns the keyspace size if known, for progress/ETA (-1 if unknown/streamed).
    Len() int64
    Reset() error // re-iterate for a new file (password promotion prepends ancestors)
}
```

Built-in sources (all in `pkg/xcrack/candidates`):

- `Explicit(passwords ...string)` — the `--password` values.
- `Wordlist(readers ...io.Reader)` — line-delimited; gzip auto-detected; `-` = stdin.
- `DefaultList()` — a small embedded list of passwords common in malware
  campaigns (empty string, `infected`, `virus`, `malware`, `password`, `123456`,
  the file/sample name, …). Always consulted first in the Impex profile.
- `Chain(...CandidateSource)` — ordered concatenation with cross-source dedup
  (bounded Bloom/-set to cap memory).

### 3.2 Pattern engine (hashcat-compatible)

Two sub-languages, both native Go, chosen for compatibility with the large body
of existing rule/mask files (see [ADR-0005](adr/0005-hashcat-compatible-pattern-engine.md)):

**Masks** — positional charset templates:

```
?l ?u ?d ?s ?a ?b   built-in sets (lower, upper, digit, special, ascii-printable, all bytes)
?1..?4              user charsets defined with --custom-charset1..4
example:  ?u?l?l?l?l?d?d        → Abcde12-style keyspace
```

**Rules** — mangling applied to each wordlist entry (hashcat rule subset for MVP):

```
:          no-op            l   lowercase      u  uppercase    c  capitalise
$X         append X         ^X  prepend X      r  reverse      d  duplicate
sXY        replace X with Y tN  toggle case @ N  TN toggle pos N   { } rotate
```

```go
package patterns

type Mask struct { /* compiled */ }
func CompileMask(spec string, custom map[rune]string) (*Mask, error)
func (m *Mask) Source() CandidateSource          // adapts a mask to a CandidateSource

type RuleSet struct { /* compiled */ }
func CompileRules(lines []string) (*RuleSet, error)
func (rs *RuleSet) Apply(word []byte) [][]byte    // all mangled variants

// Convenience: wrap a base source so every emitted word is expanded by the rules.
func WithRules(base CandidateSource, rs *RuleSet) CandidateSource
```

A thin **YAML wrapper** lets patterns be expressed readably and bundled in the
config file; it compiles down to the same masks/rules:

```yaml
patterns:
  masks:
    - "?u?l?l?l?l?d?d"
  rules:
    - "c $1 $2 $3"          # Capitalise then append 1,2,3
  custom_charsets:
    1: "abcdef0123456789"
```

### 3.3 Ordering & determinism

Candidates are emitted in a defined order — explicit passwords, then default
list, then wordlists (in argument order), then rule-expanded, then mask
keyspace — so a run is reproducible. With **password promotion**, ancestors'
successful passwords are prepended for descendant nodes.

---

## 4. Recursive decomposition algorithm

```
func decompose(ctx, node, candidates, depth):
    budget.check(depth, node.size)            # may mark StatusLimitExceeded and return
    if cycleSeen(node.sha256): mark+return

    fmt := registry.Detect(peek(node))
    content := node.bytes

    if fmt implements Encrypted:
        ch := fmt.Probe(content)
        pw, key := search(ctx, ch, promoted(candidates, depth))   # concurrent over workers
        if found:
            node.Password, node.WasEncrypted = pw, true
            promote(pw)                        # available to descendants first
            content = fmt.Decrypt(content, key)
            node.Status = StatusDecrypted
        else:
            node.Status = StatusLocked
            return                             # cannot go deeper; report locked

    materialise(content) into memory or spill   # counts against MaxTotalBytes

    isDoc := fmt.Caps().Explodable
    if fmt implements Container and not opts.NoRecurse and (not isDoc or opts.ExplodeDocuments):
        for entry in fmt.Entries(content):      # scheduled across file-jobs
            child := newNode(entry)
            node.Children.append(child)
            decompose(ctx, child, candidates, depth+1)
    else:
        node.Content = ref(content)             # leaf: hand back to caller
```

Notes:

- `search` is the only concurrent step within a node; it fans candidates across
  `Workers` goroutines and stops on first hit (unless `--find-all`).
- Every `fmt.*` call is wrapped by a `recover()` boundary that converts a panic
  in a (hostile-input-exposed) parser into a `StatusError` node — the scan
  continues. See [threat model](threat-model.md).
- `materialise` respects `SpillThreshold`: small layers stay in memory; large
  ones spill to a per-run locked temp dir, all counted against the global byte
  budget and securely removed on completion.

---

## 5. Concurrency model

See [ADR-0006](adr/0006-concurrency-model.md). Summary:

- **Axis 1 — `Workers`:** candidate testers within a single file (the KDF grind).
- **Axis 2 — `FileConcurrency`:** files/entries processed concurrently.
- **Global cap:** a single weighted semaphore sized from `MaxProcs`; total live
  workers = `FileConcurrency × Workers ≤ MaxProcs`. This keeps a 5,000-file batch
  from spawning tens of thousands of goroutines inside Impex.
- **Backpressure:** bounded channels between the candidate feeder and workers;
  `batch-size` candidates per hand-off amortises channel overhead for cheap KDFs.
- **Cancellation:** `ctx` + `Budget.PerFile`/`Budget.Total`; a cancelled search
  yields `StatusLocked` (undetermined), never a false negative claim.

---

## 6. Configuration

Precedence (highest wins): **command-line flags > environment variables >
config file > built-in defaults** (see [ADR-0008](adr/0008-config-and-output.md)).

YAML config (`--config`), example:

```yaml
concurrency:
  workers: 8
  file_jobs: 4
  max_procs: 16
limits:
  max_depth: 32
  max_total_bytes: 2147483648   # 2 GiB
  max_nodes: 10000
  max_ratio: 200
recursion:
  recurse: true
  explode_documents: false
search:
  stop_on_first: true
  promote_passwords: true
candidates:
  wordlists: [ "/opt/impex/wordlists/common.txt" ]
  use_default_list: true
patterns:
  masks: [ "?u?l?l?l?l?d?d" ]
  rules: [ "c $1" ]
output:
  format: json
  results_file: "/var/log/impex/xcrack-results.jsonl"
  redact_passwords_in_logs: true
  log_level: info
```

Environment variables use an `XCRACK_` prefix mirroring the structure
(`XCRACK_WORKERS`, `XCRACK_MAX_DEPTH`, …).

---

## 7. CLI surface (`cmd/xcrack`)

```
xcrack [flags]                 decrypt/decompose sources
xcrack identify [flags]        detect format & encryption only (no cracking)
xcrack version

I/O:
  -s, --source PATH         file, dir, or glob (repeatable); dirs need --recursive-fs
      --recursive-fs        walk directories on the host filesystem
      --input-list FILE     read source paths from FILE or - (stdin)
  -o, --out DIR             write decrypted tree here (default: stdout manifest only)
      --results-file FILE   write recovered passwords/manifest here

Candidates:
  -w, --wordlist FILE       repeatable; - for stdin; gzip auto-detected
  -p, --password STR        repeatable; explicit candidate
      --pattern FILE        mask/rule file (repeatable)
      --no-default-list     disable the built-in common-password list

Config:
  -c, --config FILE         YAML config

Concurrency (MVP subset in bold):
      --workers N           candidate testers per file            (bold)
      --file-jobs N         files processed concurrently          (bold)
      --max-procs N
      --batch-size N
      --timeout D           per-file budget                       (bold)
      --max-duration D
      --throttle PCT
      --stop-on-first / --find-all
      --keep-going / --fail-fast

Recursion / limits:
      --recurse / --no-recurse
      --explode-documents
      --max-depth N  --max-total-bytes BYTES  --max-nodes N  --max-ratio N

Output:
      --format text|json|jsonl
      --log-level debug|info|warn|error
      --audit-log FILE
```

Exit codes: `0` = at least one target decrypted/accessible, `1` = nothing
unlocked (all locked), `2` = usage/IO/internal error.

---

## 8. Error & status model

- **Per-node, recoverable:** bad crypto header, unsupported variant, limit
  breach, parser panic → recorded as `StatusError`/`StatusLocked`/`StatusLimitExceeded`
  on that node; the scan continues. This is the common case for hostile input.
- **Run-level, fatal:** invalid options, unreadable source, exhausted disk for
  spill, context cancelled at the top level → returned as `error` from `Process`.
- **Never:** a panic escaping to the caller; a plaintext password in a default-level
  log line; an unbounded allocation.

Errors are wrapped with `%w` and classified via sentinel/typed errors
(`ErrLocked`, `ErrLimitExceeded`, `ErrUnsupported`, `ErrMalformed`) so callers
can branch programmatically.

---

## 9. Testing strategy (design-level)

- **Golden sample corpus:** a committed set of small files encrypted with known
  passwords across every supported format/variant; round-trip decrypt asserted.
- **Known-answer tests** for each KDF/cipher against published vectors.
- **Fuzzing** (`go test -fuzz`) on every format `Probe`/`Entries`/`Detect` with
  the invariant: *no panic, bounded memory, terminates* on arbitrary input.
- **Bomb corpus:** zip bombs, quines, deep nesting — assert limits trigger and
  the process stays bounded.
- **Concurrency/race:** `-race` across batch runs; determinism of result ordering.
- **Parity test:** the CLI produces the same `Result` as the direct library call
  for the same inputs.
