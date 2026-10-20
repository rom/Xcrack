# Xcrack API Reference — Library and REST

Xcrack ships in three forms over one engine, with **identical cracking
capability** (ASR CON‑3):

| Form | Entry point | Audience |
|------|-------------|----------|
| **CLI** | `xcrack` (see [`USERMANUAL.md`](USERMANUAL.md), [`USAGE.md`](USAGE.md)) | operators, scripts |
| **Library** | `github.com/rom/xcrack/pkg/xcrack` | Go programs embedding the engine |
| **REST** | `xcrackd` / `github.com/rom/xcrack/pkg/api` | services, the distributed fleet |

Every CLI flag maps to a field on the library's `Options`, and the REST service
is a thin wrapper over the same `Pool`. This document is the reference for the
**library** (Part 1) and the **REST API** (Part 2). Runnable library programs
live in [`xcrack/examples/`](../xcrack/examples).

---

## Part 1 — The embeddable library (`pkg/xcrack`)

```go
import "github.com/rom/xcrack/pkg/xcrack"
```

The engine detects a file's format, decrypts it when a candidate unlocks it, and
**recursively decomposes** containers (a ZIP inside an email inside a disk image),
returning a tree of nodes. It is safe for concurrent use and resource-bounded.

### Quick start

```go
import (
	"context"
	"os"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

data, _ := os.ReadFile("secret.zip")
res, err := xcrack.Process(
	context.Background(),
	bytes.NewReader(data), int64(len(data)),
	candidates.Explicit("letmein", "hunter2"), // the candidate stream
	xcrack.Options{},                           // zero value = sensible defaults
)
if err != nil { /* ... */ }
defer res.Close()
for _, pw := range res.Passwords() {
	fmt.Println("recovered:", pw)
}
```

`Process` is the one-shot convenience. A long-lived service builds a **`Pool`**
once and reuses it (below).

### `Pool` vs `Process`

```go
func NewPool(opts Options) *Pool
func (p *Pool) Process(ctx, src io.ReaderAt, size int64, candidates CandidateSource) (*Result, error)
func (p *Pool) Metrics() Metrics
func (p *Pool) Close() error

func Process(ctx, src io.ReaderAt, size int64, candidates CandidateSource, opts Options) (*Result, error)
```

A `Pool` holds a **global semaphore** that caps total concurrent candidate
testers at `MaxProcs` across every in-flight `Process` call, so a server can call
`Process` from many request goroutines without oversubscribing the CPU. Build it
at startup, `Close` it at shutdown. `Process` (package function) is a single-use
`Pool`.

`src` must stay readable for the call; `size < 0` is treated as 0. `candidates`
may be `nil` for **identify-only** (encrypted nodes come back locked). Always
`defer res.Close()` — it releases any temp files used to spill large content.

### `Options`

The zero value is a sensible default (recurse, promote recovered passwords across
layers, stop at the first match, `NumCPU` workers). Every field:

**Concurrency & budget**

| Field | Meaning |
|-------|---------|
| `Workers int` | candidate-test goroutines within one file (0 ⇒ NumCPU) |
| `FileConcurrency int` | container entries processed concurrently (0 ⇒ NumCPU; 1 disables) |
| `MaxProcs int` | global ceiling on concurrent testers (0 ⇒ NumCPU) |
| `BatchSize int` | candidates per worker hand-off (0 ⇒ 1); amortizes channel overhead |
| `ThrottlePercent int` | approximate CPU duty cycle 1..99 (0/100 ⇒ no throttle) |
| `Budget Budget` | `PerFile` / `Total` wall-clock deadlines (0 ⇒ none) |
| `Limits Limits` | safety ceilings (depth, bytes, nodes, entry size, candidates) |

**Behaviour toggles** (zero value = the sensible default noted)

| Field | Default | Meaning |
|-------|---------|---------|
| `NoRecurse bool` | recurse | disable container decomposition |
| `NoPromote bool` | promote | disable password promotion to inner layers |
| `CorpusPromotion bool` | off | promote recovered passwords across *every* file in a run, most-successful first |
| `ExplodeDocuments bool` | off | decompose documents into their internal parts |
| `ContextCandidates bool` | off | seed guesses from the node name and plaintext sibling entries |
| `HintCandidates bool` | off | seed guesses from an embedded password hint (iWork `.iwph`, ZIP comment) |
| `HintRules func(base string) []string` | nil | expand each hint word into variants (built from a rule file) |

**Pluggable behaviour**

| Field | Meaning |
|-------|---------|
| `Registry *xfileformats.Registry` | which formats are enabled (nil ⇒ `DefaultRegistry()`) |
| `CandidateProvider CandidateProvider` | a source tried ahead of the per-call source on every `Process` |
| `KnownPlaintext KnownPlaintext` | opt-in ZipCrypto known-plaintext key recovery (no password) |
| `FastReject func(path string, cand []byte) bool` | cheap per-candidate pre-check; `true` discards before the KDF (never applied to proven passwords; cannot cause a false positive) |
| `Accelerator Accelerator` | offload the shared PBKDF2 sweep to the OpenCL tier (nil ⇒ CPU) |
| `AccelBatch int` | candidates per accelerator dispatch (0 ⇒ autotuned) |
| `DualPipeline bool` | race the CPU search and the accelerator sweep over one shared keyspace; first to find wins |

**Observability** (see [`USERMANUAL.md` §6](USERMANUAL.md#8-logging-and-the-audit-trail))

| Field | Meaning |
|-------|---------|
| `OnFound func(Found)` | called when a node is unlocked; **carries the password** |
| `OnProgress func(Progress)` | periodic progress during a search |
| `OnAudit func(AuditEvent)` | one secrets-free event per node after a call (for an audit log) |
| `AuditIncludeSecrets bool` | let `OnAudit` carry the recovered password (opt-in) |
| `Logger Logger` | structured diagnostics sink (`Debugf/Infof/Warnf/Errorf`) |

`DefaultOptions()` returns the explicit defaults; `DefaultLimits()` the limit
floors. `DefaultRegistry()` is the standard format set; `ForceRegistry(name)`
builds a single-format registry for a magic-less format (`"sqlcipher"`,
`"vbaproject"`) — the library equivalent of the CLI's `--as`.

### Candidate sources (`github.com/rom/xcrypto/candidates`)

`CandidateSource` is an alias for `candidates.Source` (`Next() ([]byte, error)`,
`Len() int64`, `Reset() error`). The `candidates` package is the full generator
toolkit the CLI flags are built on — compose it directly:

```go
src := candidates.Dedup(candidates.Chain(
	candidates.File("rockyou.txt"),             // a wordlist
	candidates.ToggleCase(base, 4),             // case variants
	candidates.Prince(base, 6, 16, 3, 200_000), // length-ordered concatenations
	candidates.MarkovGen(model, 4, 12, 200_000),// a trained Markov model, best-first
))
src = candidates.Shard(src, 0, 4)               // this worker's stride of the keyspace
```

Key constructors: `Explicit`, `Bytes`, `File`, `Reader`, `Stdin`, `DefaultList`,
`Swedish`, `Chain`, `Dedup`, `Shard`, `LengthFilter`, `Encode`/`ParseEncoding`,
`Combinator`, `ToggleCase`, `Prince`, `KeyboardWalk`, `MarkovGen`/`MarkovGenTopK`
(after `TrainMarkov`), `MarkovGenPos` (after `TrainMarkovPos`), `TrainPCFG`,
`Context`/`FromName`/`FromText`/`FromHint`, `Spray`/`SprayCommon`,
`BreachCorpus`/`BreachFile`, `ByScore`, `Checkpoint`. Mask/rule expansion lives in
`github.com/rom/xcrypto/pattern`. See [`candidate-pipeline`](../xcrack/examples/candidate-pipeline).

### Results

```go
type Result struct { Root *Node; Stats Stats; /* ... */ }
func (r *Result) Passwords() []string   // distinct recovered passwords, first-seen order
func (r *Result) Close() error          // release spilled temp files

type Node struct {
	Path          string        // lineage, e.g. "invoice.zip!/report.docx"
	Format        string        // detected format ("" = plaintext/unknown leaf)
	WasEncrypted  bool
	Password      string        // the candidate that unlocked this node ("" if none)
	KeyRecovered  bool          // unlocked by known-plaintext key recovery (no password)
	CrackDuration time.Duration // per-node time-to-crack
	Status        NodeStatus    // StatusPlain|Decrypted|Locked|LimitExceeded|Error
	Err           error
	Content       ContentRef    // on-demand bytes (nil for non-leaf / locked)
	Children      []*Node
}
func (n *Node) Walk(fn func(*Node))                 // pre-order
func (n *Node) AuditEvent(includeSecrets bool) AuditEvent
```

`ContentRef` yields a node's bytes lazily (`Open() (io.ReadCloser, error)`,
`Size() int64`, `SHA256() [32]byte`) so a large tree never sits fully in RAM.
`BuildReport(res)` renders the tree as the JSON `Report` the REST API returns.
See [`inspect-tree`](../xcrack/examples/inspect-tree).

### Callbacks

- **`OnFound(Found)`** — `{Path, Format, Password, KeyRecovered}`; the one place
  the password is delivered.
- **`OnProgress(Progress)`** — `{Path, CandidatesTried, Depth, BytesExtracted}`.
- **`OnAudit(AuditEvent)`** — one event per node for an audit trail; secrets-free
  unless `AuditIncludeSecrets` is set.
- **`CandidateProvider`** — `Candidates(ctx) CandidateSource`, tried ahead of the
  per-call source on every `Process` (plug a live/org-wide list once instead of
  threading it through each call). `CandidateProviderFunc` adapts a function.

### Advanced embedding

- **Known-plaintext (ZipCrypto):** set `Options.KnownPlaintext.For = func(path) []byte`
  to return known leading bytes of an entry; the internal key is recovered with no
  password. `Offload` runs it on an external engine (e.g. `zipcrypto.ExternalBkcrack`).
- **FastReject:** encode a domain constraint (e.g. "the secret is a 6-digit PIN")
  to prune a hopeless keyspace before the KDF — see [`pin-fastreject`](../xcrack/examples/pin-fastreject).
- **Accelerator / DualPipeline:** hand the engine an `accel.Accelerator` (the
  OpenCL tier, `-tags opencl`) to offload the PBKDF2 sweep; add `DualPipeline` to
  run the CPU and the device concurrently over one keyspace.
- **Logging:** build the structured/syslog logger with
  `github.com/rom/xcrack/pkg/auditlog` (`New`, `Printf`, `Sink`, `LogFile`) — the
  same one the CLI and `xcrackd` use.

### Example programs

| Example | Shows |
|---------|-------|
| [`impex-embed`](../xcrack/examples/impex-embed) | the minimal embedding: one Pool, in-memory candidates, `OnFound` |
| [`batch-triage`](../xcrack/examples/batch-triage) | concurrent triage of many files through one Pool, JSON per file, aggregate `Metrics` |
| [`candidate-pipeline`](../xcrack/examples/candidate-pipeline) | composing an advanced candidate stream + `CandidateProvider` |
| [`pin-fastreject`](../xcrack/examples/pin-fastreject) | `FastReject` keyspace pruning + a custom `Source` |
| [`inspect-tree`](../xcrack/examples/inspect-tree) | identify-only traversal of the `Result`/`Node` tree + `ContentRef` |
| [`http-service`](../xcrack/examples/http-service) | embedding the REST API (`pkg/api`) in your own server |

---

## Part 2 — The REST API (`xcrackd` / `pkg/api`)

`xcrackd` serves the engine over HTTP; `pkg/api` is the embeddable handler
(`api.NewServer(pool, cfg).Handler()`). It adds only transport concerns — body
limits, deadlines, method/path checks, JSON — over a shared `Pool`.

> **Security:** the service ships **no user authentication**. Put authn/z in
> front of it. It can terminate **TLS** itself (below) or run plaintext behind a
> TLS-terminating proxy. Recovered passwords and decrypted content appear in
> responses.

### Running the server

```sh
xcrackd -addr :8080                 # plaintext (trusted network only)
xcrackd -addr :8443 --tls-cert server.crt --tls-key server.key   # HTTPS
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-addr` | `:8080` | listen address |
| `-workers` / `-max-procs` / `-file-jobs` | NumCPU | engine concurrency (as the library fields) |
| `-batch-size` / `-throttle` | auto / off | worker hand-off size / CPU duty cycle |
| `-no-recurse` / `-explode-documents` | recurse / off | container decomposition controls |
| `-context` / `-hint` | off | name/sibling- and hint-derived candidates |
| `-max-depth` / `-max-nodes` / `-max-total-bytes` / `-max-entry-size` / `-max-candidates` | defaults | engine limits |
| `-max-body` | 256 MiB | maximum request body |
| `-request-timeout` | 120s | per-request processing deadline |
| `-read-timeout` / `-write-timeout` / `-shutdown-grace` | 30s / 150s / 20s | HTTP timeouts |
| `-allow-default-list` | off | permit `?defaults=true` to use the embedded wordlist |
| `-gpu` / `-gpu-selftest` / `-dual-pipeline` | off | OpenCL tier (needs `-tags opencl`); dual CPU+GPU pipeline |
| `-tls-cert` / `-tls-key` | — | serve HTTPS |
| `-tls-client-ca` | — | require & verify client certs (mutual TLS) |
| `-tls-min-version` | 1.2 | TLS floor (`1.2`\|`1.3`) |
| `-log-level` / `-log-format` / `-log-file` / `-syslog` / `-syslog-address` / `-syslog-network` / `-syslog-tag` | | the shared logger (see manual §6) |
| `-audit-log-password` | off | include the recovered password in the audit trail |

### Endpoints

| Method / path | Purpose |
|---------------|---------|
| `GET /v1/healthz` | liveness probe → `{"status":"ok"}` |
| `GET /v1/metrics` | aggregate `Pool` counters as JSON (`Metrics`) |
| `GET /metrics` | the same counters in Prometheus text format |
| `POST /v1/identify` | detect format/encryption only — no candidates, no cracking |
| `POST /v1/decrypt` | decrypt + recursively decompose with the supplied candidates |

### Request shapes

Both POST routes accept two content types:

1. **`application/octet-stream`** (default) — the raw file is the body; candidates
   come from the query string.
2. **`multipart/form-data`** — a `file` part carries the archive and an optional
   `wordlist` part carries newline-delimited candidates (so an orchestrator can
   ship a large keyspace stripe in one request). The values below also work as
   form fields.

| Parameter | Where | Meaning |
|-----------|-------|---------|
| `password` | query (repeatable) / form | an explicit candidate (capped by the server's `MaxPasswords`, default 10000) |
| `defaults=true` | query / form | append the embedded default list (only if `-allow-default-list`) |
| `shard=I/N` | query / form | test only stride *I* of *N* of the keyspace |
| `max-duration` | query | a shorter per-request deadline (never longer than the server's) |
| `wordlist` | multipart file part | newline-delimited candidates |

```sh
# octet-stream, candidates on the query string:
curl --data-binary @secret.zip 'http://host:8080/v1/decrypt?password=letmein&password=hunter2'

# multipart, shipping a wordlist stripe:
curl -F file=@secret.zip -F wordlist=@stripe.txt -F shard=0/4 http://host:8080/v1/decrypt

# identify only:
curl --data-binary @unknown.bin http://host:8080/v1/identify
```

### Response

Both POST routes return the JSON `Report` (HTTP 200 even when nothing cracked —
inspect `status`/`recovered_passwords`):

```json
{
  "root": {
    "path": "", "format": "zip", "status": "plain", "encrypted": false,
    "children": [
      { "path": "secret.txt", "format": "", "status": "decrypted",
        "encrypted": true, "password": "hunter2", "size": 1024,
        "sha256": "…" }
    ]
  },
  "recovered_passwords": ["hunter2"],
  "stats": { "files_seen": 2, "candidates_tried": 2, "bytes_extracted": 1024,
             "limit_hits": 0, "elapsed_ms": 3 }
}
```

Errors are JSON `{"error":"…"}` with a 4xx/5xx status (`405` wrong method, `400`
bad/empty body, `413` too large, `504` deadline exceeded, `500` processing error).

### TLS

`xcrackd` terminates TLS with `--tls-cert`/`--tls-key` (and `--tls-client-ca` for
mutual TLS). Generate certs with
[`scripts/gen-selfsigned-cert.sh`](../scripts/gen-selfsigned-cert.sh) (self-signed
or a full mTLS kit) or [`scripts/gen-letsencrypt-cert.sh`](../scripts/gen-letsencrypt-cert.sh)
(ACME). The `xcrack` client trusts a private cert with `--tls-ca` and presents a
client cert with `--tls-cert`/`--tls-key`. See
[`USERMANUAL.md` §4](USERMANUAL.md#securing-the-link-with-tls).

### Parity model — how the rich attacks reach the server

The REST request vocabulary is deliberately small (explicit passwords, the
default list, a shipped wordlist, a shard). The **full candidate toolkit**
(rules, masks, Markov/PCFG, combinator, hybrid, PRINCE, spray, breach, context,
hint) runs **client-side**: the `xcrack` distributed orchestrator
(`pkg/cluster`) builds the complete stream from its flags and ships it to the
fleet as batches, so any CLI attack works distributed without the server needing
a flag for it. The server stays a fast, stateless **verify/KDF worker**; the
client owns candidate generation. This keeps the three forms at parity while the
wire protocol stays simple. See [`USERMANUAL.md` §4](USERMANUAL.md#5-distributed-environments).

---

## Part 3 — The Web API (`xcrack-web` / `pkg/webui`)

`xcrack-web` serves a browser GUI backed by a JSON/SSE API. Unlike the `xcrackd`
REST worker (a stateless verify/KDF node), this API drives **whole jobs**: it
accepts uploaded files plus a `jobspec.Spec` (the config YAML), runs the full
engine — every candidate source the config can express — and streams progress
and results. It is the delivery surface for an interactive recovery console,
running single-user (the default) or multi-user with per-user job ownership
behind OIDC; see [`USERMANUAL.md` §10](USERMANUAL.md#10-web-gui-xcrack-web).

### Running the server

```sh
bin/xcrack-web                          # http://127.0.0.1:8899 (localhost, single-user)
bin/xcrack-web --addr :9000             # all interfaces (single-user ships no auth — see §10.13)
bin/xcrack-web --mode multi \           # multi-user: per-user jobs behind OIDC (see §10.2)
  --auth-oidc-issuer https://idp/ --auth-oidc-client-id xcrack-web \
  --auth-redirect-url https://host/auth/callback   # secret in $XCRACK_WEB_OIDC_CLIENT_SECRET
```

In multi-user mode the API endpoints below (except `/healthz`, `/meta`, `/me`
and `/auth/*`) require a signed-in session and are scoped to the owner.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/healthz` | liveness probe |
| `GET` | `/api/v1/meta` | capabilities (version, GPU/TPM build, TLS, whether auth is on), supported formats, a starter spec |
| `GET` | `/api/v1/me` | the signed-in user (or the implicit local owner in single-user mode) |
| `GET` | `/auth/login` / `GET /auth/callback` / `POST /auth/logout` | OIDC sign-in / provider redirect / sign-out (multi-user mode) |
| `POST` | `/api/v1/config/validate` | strict-parse + validate a YAML spec (`{valid, error}`) |
| `POST` | `/api/v1/config/format` | re-emit a spec tidied (`{yaml}`) |
| `POST` | `/api/v1/identify` | detect format/encryption of uploaded files (no cracking) |
| `POST` | `/api/v1/inspect` | feasibility estimate (multipart: `spec` + `source` + `aux`): per-file keyspace, verify rate, time-to-exhaust, and a bounded candidate-stream preview — the CLI's `--keyspace`/`--benchmark`/`--estimate`/`--stdout`, runs nothing and persists no job |
| `POST` | `/api/v1/jobs` | create a job (multipart: `spec` + `source` files + `aux` files) |
| `GET` | `/api/v1/jobs` / `/api/v1/jobs/{id}` | list jobs / one job's state + results |
| `DELETE` | `/api/v1/jobs/{id}` | remove a finished job from the history |
| `GET` | `/api/v1/jobs/{id}/events` | Server-Sent Events: live progress/log/found/state |
| `GET` | `/api/v1/events` | Server-Sent Events: a contentless `changed` nudge whenever any job is created/updated/removed, so the History/Statistics/Recovered/Audit lists update live (each list re-fetch is still access-filtered) |
| `POST` | `/api/v1/jobs/{id}/cancel` | cancel a running job |
| `POST` | `/api/v1/jobs/{id}/rerun` | start a new job from a finished/interrupted job's saved spec + uploads (owner/admin). A single-target job's **checkpoint** is carried forward, so re-running an interrupted run **resumes** near where it stopped rather than restarting (the job view's `resumable` flag marks such jobs) |
| `POST` | `/api/v1/jobs/{id}/share` | set the subjects granted read access to a job (`{subjects:[...]}`; owner/admin, multi-user mode) |
| `GET` | `/api/v1/jobs/{id}/download` | the decrypted output tree as a zip |
| `GET` | `/api/v1/jobs/{id}/report` | a self-contained forensic report for the job — case metadata (`case_id`/`examiner`, set at submission), the per-node recovery results with each node's SHA-256, and the job's chain of custody (its audit-trail entries). `?format=html` (default, printable) or `?format=csv`. Passwords are shown only under `--expose-secrets` |
| `GET` | `/api/v1/stats` | aggregate counters across jobs |
| `GET` | `/api/v1/audit` | the access/action audit trail (admin-only; newest first) — who ran what, when, from where; never records recovered secrets |
| `GET` | `/api/v1/vault` | the recovered-password vault (single-user, `--expose-secrets`; off under multi-user) |
| `GET`/`POST` | `/api/v1/library` | list / upload reusable wordlists |
| `GET` | `/api/v1/library/{name}/preview` | first lines of a library wordlist |
| `DELETE` | `/api/v1/library/{name}` | delete a library wordlist |
| `POST` | `/api/v1/cluster/health` | ping configured `xcrackd` servers (`--allow-server-paths`) |
| `POST` | `/api/v1/tools/{hashline,vba-recover,access-recover,export-challenge,wordlist,rule-test,pdf-keyattack-table}` | specialist, mostly-stateless tools (see §10.9) |
| `POST` | `/api/v1/tools/kp` | ZipCrypto known-plaintext (Biham–Kocher) key recovery, run as a background **job** (multipart: `plain` + `cipher`, optional `zip` + `entry` + `offset` for whole-archive decrypt). Returns a job `id`; stream `/jobs/{id}/events` and download via `/jobs/{id}/download`. The in-process attack is compute-heavy; the external bkcrack offload stays CLI-only |
| `GET` | `/api/v1/docs` / `/api/v1/docs/{name}` | in-app documentation listing / Markdown |

### Submitting a job

A job is `multipart/form-data`:

- `spec` — the job configuration as YAML (or JSON; it is parsed as YAML). This
  is a `jobspec.Spec` — the schema in [`config/README.md`](../config/README.md).
- `source` — one or more parts: the files to recover.
- `aux` — zero or more parts: wordlists / breach corpora / combinator / hcmask
  inputs the spec references by **base name**.
- `case_id`, `examiner` — optional forensic case metadata recorded on the job and
  surfaced in its report (`/jobs/{id}/report`).
- `recovered` — zero or more parts: a solved-challenge payload (a
  `RecoveredPassword` JSON object, or a JSON array of them) exported earlier via
  `/tools/export-challenge` and solved on an external cracker. Its passwords are
  tried **first** on every file (the GUI equivalent of the CLI `--resume-from`);
  the job view reports how many as `resume_count`.

```sh
curl -sS -X POST http://127.0.0.1:8899/api/v1/jobs \
  -F 'spec={"candidates":{"use_default_list":false,"wordlists":["rockyou.txt"]}}' \
  -F 'source=@secret.docx' \
  -F 'aux=@rockyou.txt'
# => {"id":"…"};  then GET /api/v1/jobs/{id} or stream /events
```

### Security & parity

The backend builds engine `Options` and the per-file candidate source from the
spec through `pkg/jobspec` — the same assembler the CLI uses — so the GUI reaches
the full attack toolkit directly (no client-side orchestration needed, unlike
the REST worker). It ships no authentication (localhost is single-user; a shared
instance needs a proxy + TLS). A submitted spec may reference only uploaded files
(file-path fields are resolved within the job's upload area and anything
escaping is rejected) unless `--allow-server-paths` is set; output destinations
in a spec are ignored. Recovered passwords appear in responses/events only when
`--expose-secrets` is on.
