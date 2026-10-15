# Xcrack — Architecturally Significant Requirements (ASR)

An ASR is a requirement that, if changed, would change the architecture. This
document captures the quality attributes, constraints, and the few functional
requirements that are architecturally load-bearing. Each has an ID, a priority
(H/M/L), a concrete scenario, and the architectural response.

Priorities: **H** = must hold for v1; **M** = strongly desired; **L** = later.

---

## 1. Business context & primary use case

Xcrack exists to let the **Impex** malicious-content scanner see inside files it
would otherwise be blind to. Attackers deliberately wrap payloads in
password-protected archives and documents to evade scanning. The architecture is
therefore optimised for *"decrypt and decompose an untrusted file quickly and
safely, using mostly-known candidate passwords"* — not for grinding a single
file against an enormous keyspace.

---

## 2. Quality-attribute requirements

### QA-1 — Safety under hostile input (H)
**Scenario:** Impex feeds Xcrack a file crafted to crash or exhaust it (malformed
crypto header, zip bomb, 10,000-deep nesting, a zip quine).
**Response required:** No panic escapes to the caller; memory and CPU stay within
configured ceilings; the process does not hang; the offending file yields a
reported error/limit node, not a crash.
**Architectural impact:** assume-hostile parsers, bounded `io.ReaderAt` wrappers,
`recover()` boundaries at every format call, a global [budget model](adr/0004-hostile-input-safety-budgets.md),
cycle detection by content hash.

### QA-2 — No content execution (H)
**Scenario:** A decrypted file is a weaponised Office document with macros or an
exploit for a document renderer.
**Response required:** Xcrack never executes, renders, or semantically interprets
content; it only derives keys and moves bytes.
**Architectural impact:** pure-Go reimplementation; **no** shelling out to Office/
LibreOffice/PDF renderers ([ADR-0001](adr/0001-pure-go-no-external-binaries.md)).

### QA-3 — Embeddability (H)
**Scenario:** Impex, a long-running service, embeds Xcrack and calls it from many
request goroutines under a fixed resource envelope.
**Response required:** Clean Go API, no global mutable state required, no external
processes, no network, `context`-based cancellation, a reusable bounded `Pool`.
**Architectural impact:** library-first design; `Options`/`Pool`; explicit format
registry; see [design §2](design.md#2-xcrack-engine-api--what-impex-embeds).

### QA-4 — Reusability of format knowledge (H)
**Scenario:** A different internal tool needs "detect + unlock + list entries"
without any cracking machinery.
**Response required:** Format knowledge is importable on its own, free of
candidate/concurrency/recursion policy.
**Architectural impact:** the standalone **Xfileformats** module
([ADR-0002](adr/0002-standalone-xfileformats-library.md)).

### QA-5 — Throughput & resource predictability at batch scale (H)
**Scenario:** Impex scans thousands of files per minute; each has a small
candidate set.
**Response required:** Concurrency scales with cores along two independent axes
but total live work is globally bounded, so the host's memory/CPU envelope is
never exceeded regardless of batch size.
**Architectural impact:** two-axis scheduler + single global semaphore
([ADR-0006](adr/0006-concurrency-model.md)); probe-once/test-many hot path.

### QA-6 — Correctness / no false positives (H)
**Scenario:** Xcrack reports a file as decrypted with password X.
**Response required:** The claim is verified against the format's own verifier and
the decrypted bytes are the real plaintext — never a guess or partial match.
**Architectural impact:** `Verify` returns the derived key only on a confirmed
verifier match; round-trip golden tests and known-answer vectors.

### QA-7 — Recursion correctness (H)
**Scenario:** A password-protected ZIP contains an encrypted `.docx` containing
further nested archives.
**Response required:** Every layer is independently detected, unlocked, and
decomposed to arbitrary (bounded) depth; results form a faithful tree; both the
password and the content of each layer are reported.
**Architectural impact:** the [recursive decomposition model](adr/0003-recursive-decomposition-model.md)
and the `Node` tree.

### QA-8 — Secret hygiene (M)
**Scenario:** Logs from a scan are shipped to a central store.
**Response required:** Recovered passwords are not written to logs at default
levels; they are delivered only via the result/results-file; errors are redacted.
**Architectural impact:** a redacting logger; passwords confined to `Node.Password`
and `Found` callbacks.

### QA-9 — Observability & SLAs (M)
**Scenario:** Impex must bound each file to an SLA and report progress.
**Response required:** Per-file and whole-run deadlines; progress/`found`
callbacks; graceful "gave up / undetermined" signalling.
**Architectural impact:** `context` threading; `Budget`; `OnProgress`/`OnFound`.

### QA-10 — Extensibility (M)
**Scenario:** A new encrypted format must be supported.
**Response required:** Add one `Format` plugin to Xfileformats; the engine and CLI
need no change.
**Architectural impact:** the `Format`/`Encrypted`/`Container` interfaces + registry.

### QA-11 — Determinism / reproducibility (M)
**Scenario:** A scan is re-run on the same inputs for investigation.
**Response required:** Candidate ordering and traversal order are deterministic;
the same inputs yield the same result tree.
**Architectural impact:** defined candidate ordering; stable entry enumeration.

### QA-12 — Portability (M)
**Scenario:** Impex runs on Linux containers (amd64/arm64) and developers on macOS.
**Response required:** A single pure-Go build, cross-compilable, no cgo required.
**Architectural impact:** stdlib-first crypto; third-party pure-Go libs only.

---

## 3. Constraints

| ID | Constraint | Rationale |
| -- | ---------- | --------- |
| CON-1 | **Pure Go, no external binaries, no cgo (default)** | Safety (QA-2), portability (QA-12), embeddability (QA-3). |
| CON-2 | **No network / no online attacks** | Scope & authorized-use posture; offline-only against a file's own KDF. |
| CON-3 | **Full CLI/library parity** | Every CLI capability is a library `Options` field; the CLI adds no hidden behaviour. |
| CON-4 | **Two modules, one repo** | Xfileformats importable alone (QA-4); engine/CLI separate. |
| CON-5 | **Go 1.23+, MIT, minimal vetted dependencies** | Build simplicity; licence compatibility for embedding. |
| CON-6 | **No plaintext spillage** | Decrypted (potentially malicious) content stays in memory or a locked, wiped temp dir; not written unless the caller asks. |
| CON-7 | **Authorized-use framing in docs & CLI help** | Defensive/recovery tool; operated against owned/authorized data. |

---

## 4. Architecturally significant functional requirements

| ID | Requirement | Priority |
| -- | ----------- | -------- |
| FR-1 | Detect format and encryption state of an arbitrary byte stream. | H |
| FR-2 | Test candidate passwords (explicit, wordlist, default list, generated) against a probed challenge and confirm correctness. | H |
| FR-3 | Decrypt a file with the working password and return its plaintext as a stream. | H |
| FR-4 | Recursively decompose nested containers/encryption to bounded depth, reporting a tree. | H |
| FR-5 | Report, per node, both the password used and the decrypted content. | H |
| FR-6 | Accept candidates programmatically in-memory (not only from files), for Impex per-scan injection. | H |
| FR-7 | Expand masks and apply mangling rules (hashcat-compatible) to generate candidates. | M |
| FR-8 | Promote a layer's successful password to the front of candidates for inner layers. | M |
| FR-9 | Optionally explode documents into internal parts (`--explode-documents`). | M |
| FR-10 | Provide a reusable bounded `Pool` for long-running embedding. | H |
| FR-11 | Checkpoint/resume a long single-file search. | L |

---

## 5. Explicit non-goals (v1)

- No GPU/OpenCL acceleration.
- No distributed/multi-machine cracking.
- No network or online/remote attacks of any kind.
- No cryptographic exploits or weakening of sound ciphers (offline guessing only).
- No full-disk / volume encryption (BitLocker, FileVault, LUKS, VeraCrypt) in v1.
- No document rendering or macro analysis (that is Impex's job; Xcrack only
  exposes the bytes).

---

## 6. Traceability

Each ASR is realised by one or more ADRs and design sections; conversely every
ADR cites the ASR(s) it serves. The MVP ([mvp.md](mvp.md)) implements all **H**
items for the first format tier; **M**/**L** items are scheduled in the
[roadmap](roadmap.md).
