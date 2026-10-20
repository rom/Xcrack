# Changelog

All notable changes to Xcrack. The format follows
[Keep a Changelog](https://keepachangelog.com/); the project has not yet cut
tagged releases, so entries are grouped by the pull request that landed them
(newest first) with the merge date. Dates are UTC.

Scope note: Xcrack is a defensive / recovery tool. Every cryptographic scheme is
cross-validated against an external oracle (known-answer vectors or a real CLI),
hostile-input parsers are fuzzed, and the default build stays pure-Go and
CPU-only (the GPU tier is an opt-in, hardware-gated server exception).

## [Unreleased]

Work on branch `claude/loving-wozniak-mmti5f`, not yet merged.

### Added
- **Web GUI — transport hardening & retention (CSRF, rate limiting, work-dir
  caps).** `xcrack-web` now wraps the whole application in two always-on guards
  (active in single- and multi-user mode alike, since a localhost instance is
  still reachable by a malicious page via DNS-rebinding/localhost CSRF): a
  **CSRF guard** that refuses a cross-origin state-changing request using the
  `Sec-Fetch-Site`/`Origin`/`Referer` headers the browser sets itself (a
  non-browser client such as `curl` or the CLI, which sends none, is unaffected
  — there is nothing to forge), replacing the previous reliance on
  `SameSite=Lax` alone; and a per-client-IP **rate limiter** (`--rate-limit`,
  default 1200/min, with a stricter `--auth-rate-limit`, default 20/min, on the
  login endpoint; `--trust-proxy` to read `X-Forwarded-For` behind a trusted
  proxy). It also adds **retention** so a long-lived shared instance's work
  directory cannot grow without bound: `--max-retained-jobs` (prune the oldest
  finished jobs beyond a cap), `--max-job-age` (prune finished jobs older than a
  duration), and `--max-workdir-bytes` (reject a new job/inspect with HTTP 507
  once the work directory is full). None require any change to the SPA.
- **Web GUI — server-side feasibility estimate (`◴ Estimate`).** A new
  `POST /api/v1/inspect` endpoint and an **Estimate** button in the Crack tab
  answer "how long will this take, is it even worth starting" *before* a job
  runs — the CLI's `--keyspace`/`--benchmark`/`--estimate`/`--stdout`, which had
  no server-side equivalent (the wizard's existing readout is client-side
  keyspace math only). It takes the same submission as a job (spec + source +
  aux + library), and per target reports the detected scheme, the candidate
  **keyspace** (exact for finite sources, counted to a cap otherwise), the
  measured **verify rate** for that file's format, and the resulting
  **time-to-exhaust** (and ~half that expected to a hit), plus a bounded preview
  of the exact candidate stream the attack would try. It runs nothing
  destructive and persists no job — all work happens in an ephemeral temp
  directory removed before the response.
- **Web GUI — expanded attack wizard.** The `xcrack-web` wizard now composes a
  whole attack from what you know, not just a prefix/suffix and length. It adds
  **presets** (Personal, Corporate policy, Passphrase, PIN/numeric, Keyboard
  pattern); an **attack-kind** selector (recognisable word → dictionary + rules,
  random → brute force, number → digits, or both); **mangling → rules** —
  capitalise/ALL-CAPS/leet/append-digits/append-`!` and significant years
  compiled into the cross-product of real hashcat rules plus a hybrid digit
  append; a **wordlist picker** (built-in list or a saved Library list); more
  **extra sources** (keyboard walks, PRINCE, case toggles, loopback); and a
  **live feasibility estimate** that shows the brute-force keyspace and a plain
  verdict (small/moderate/large/impractical) before you run. Frontend-only —
  every option maps to existing engine capabilities via the Crack form.
- **Web GUI — explicit `--mode single|multi` run-mode switch.** `xcrack-web`
  now selects single- vs multi-user access with a first-class `--mode` flag
  (`single`, the default no-login console, or `multi`, per-user access via
  OIDC) instead of inferring it from the presence of `--auth-*` flags. `--mode
  single` rejects stray `--auth-*` flags and `--mode multi` requires the OIDC
  issuer/client-ID/redirect, so a half-configured provider can never silently
  leave the console open.
- **Web GUI — UX polish: command palette, shareable configs, trust banners.**
  `xcrack-web` gains a round of usability work. A **command palette**
  (<kbd>⌘/Ctrl-K</kbd>) jumps to any tab and triggers common actions by name;
  <kbd>⌘/Ctrl-Enter</kbd> validates-and-runs from anywhere. **Shareable config
  links** let the Configuration tab copy the current spec into a URL fragment
  (base64url, so the spec never leaves the browser or hits the server log) that
  reopens pre-filled, and an **Import…** button loads a spec from a pasted or
  uploaded YAML/JSON file (validated through `/api/v1/config/validate` before it
  is applied). **Trust banners** warn, from the bootstrap `meta` (`tls`,
  `auth_enabled`), when a console that exposes secrets is reachable over plain
  HTTP without auth — a nudge to add TLS or turn on OIDC before sharing. The
  layout is now **responsive**, usable down to a phone-width screen. (`Config`
  gains `TLS`; `meta` reports `tls` and `auth_enabled`.)
- **Web GUI — wordlist library, job-concurrency cap, cluster health & status.**
  `xcrack-web` gains several operator features: a **wordlist library** (a new
  **Library** tab — upload dictionaries once, reused by name across jobs via the
  Crack form's *Library wordlists* field, with preview/delete;
  `GET/POST/DELETE /api/v1/library`); a **job-concurrency cap** (`--max-jobs N`,
  default unlimited) so jobs beyond the cap stay **queued** until a slot frees; a
  **cluster health check** (`POST /api/v1/cluster/health`, gated behind
  `--allow-server-paths`) that pings each configured `xcrackd` server's health
  endpoint and reports up/down + latency in the Distributed panel; a **System &
  acceleration** card on the Statistics tab (GPU-tier / TPM-build / version); and
  **live-log controls** (autoscroll toggle + copy).
- **Web GUI — attack wizard, mask builder, rule tester & ETA.** `xcrack-web`
  gains guidance for building an attack: a **wizard** ("what do you know about
  the password?" — known prefix/suffix, length range, character types, personal/
  org words) that fills the Crack form (explicit guesses, length limits, spray +
  context, and an optional brute-force mask with increment); a **mask builder**
  with a live keyspace counter that inserts `?l?u?d?s?a` masks; a **rule tester**
  (`POST /api/v1/tools/rule-test`) that shows, per rule, what the engine's real
  hashcat-rule compiler does to a sample word (output or rejection); and a live
  **ETA** on determinate runs (keyspace ÷ current rate) with an honest nudge that
  an impractically long brute force is better served by a wordlist + rules.
- **Web GUI — recovered-password vault & job re-run.** `xcrack-web` now keeps a
  server-side found-password vault (potfile) under its work directory: every
  recovered password is stored and fed back into new jobs' loopback pass, so a
  reused or previously found password is caught fast. A new **Recovered** tab
  lists the vault (with whether it is plaintext or TPM-sealed at rest — the
  binary can supply a sealer via `Config.Sealer`). The vault is a single-user,
  `--expose-secrets` feature and is disabled when multi-user auth is on, so it
  never leaks passwords between users. Each History row also gains **re-run**:
  `POST /api/v1/jobs/{id}/rerun` starts a fresh job from a finished or
  interrupted job's saved spec and already-uploaded files — a GUI "resume" that
  needs no re-upload (`GET /api/v1/vault` is new).
- **Web GUI — optional multi-user access via OIDC.** `xcrack-web` can now front
  the console with an OpenID Connect identity provider, turning the single-user
  tool into a shared service. It is **off by default** — a localhost instance is
  unchanged — and enabled with `--auth-oidc-issuer` (plus `--auth-oidc-client-id`,
  `--auth-redirect-url`, and the client secret in `XCRACK_WEB_OIDC_CLIENT_SECRET`).
  Login uses the Authorization Code flow with PKCE; a verified session is held in
  an HttpOnly, SameSite=Lax, Secure cookie (relax with `--auth-cookie-insecure`
  for plain-HTTP testing). Each job is **owned by its creator**: the job list,
  detail, event stream, download, cancel and delete are scoped to the owner, and
  a non-owner's access to someone else's job is a 404 (its existence is hidden).
  `--auth-admins` (subjects or emails) may see and manage every user's jobs. The
  statistics are likewise per-user. The SPA shows a sign-in gate when required and
  a user chip + logout when signed in. New endpoints: `GET /api/v1/me`,
  `GET /auth/login`, `GET /auth/callback`, `POST /auth/logout`. (Adds the pure-Go
  `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2` dependencies; the
  default build stays cgo-free.)
- **Web GUI — job history, durability & completion notifications.** `xcrack-web`
  now persists every job to its working directory (`job.json`, written
  atomically as the job progresses), so the job list survives a server restart
  instead of living only in memory. A new **History** tab lists past and running
  jobs (state, files, decrypted count, candidates, created time); **open** reloads
  one into the results panel — resuming the live stream if it is still running,
  or showing the saved snapshot and re-download link if it finished — and
  **delete** removes a job and its working files (canceling it first, and
  draining the runner so cleanup never races it). A job still queued/running when
  the server restarted reloads as **interrupted** rather than a perpetual
  "running". An opt-in **"notify me when a job finishes"** toggle raises a browser
  notification (and an in-page toast) on completion or a recovered password, and
  a running job's progress now shows in the browser **tab title** so a
  backgrounded tab is a glanceable progress bar. (`DELETE /api/v1/jobs/{id}` is
  new; `GET /api/v1/jobs` now spans restarts.)
- **`thunder-gen` checkpoint/resume.** Table generation now writes each
  sub-table to `--out` as it finishes (flushed to disk), so a long run is no
  longer all-or-nothing: if it is interrupted (Ctrl-C), crashes, or the GPU
  resets, re-running the **same command** continues from the last completed
  sub-table instead of restarting. A truncated trailing record from a mid-write
  crash is discarded on resume. The file is a complete, usable table the moment
  the last sub-table is written (same format as before — no finalize step), and
  re-running a finished build reports "already complete" and does nothing. A
  `--out` whose header does not match the requested `--bits`/`--length`/`--tables`
  is refused rather than silently overwritten. (`pdf.TableParams` gains
  `ResumeFile`/`OnResume`.)
- **Web GUI — Tools tab (specialist subcommands).** `xcrack-web` gains a **Tools**
  view exposing the CLI's non-cracking subcommands. The quick, stateless ones run
  in the browser against new synchronous `/api/v1/tools/*` endpoints that reuse
  the same library functions as the CLI: **Identify** (format / encrypted /
  container / explodable), **Hash lines** (`$office$`/`$pdf$`/`$zip2$`… for
  hashcat/John), **VBA project password**, **Access (Jet) password**, **Export
  challenge** (downloads the portable JSON envelope for an external cracker, to
  bring back with `--resume-from`), the **PDF 40-bit thunder-table lookup**, and
  **wordlist utilities** (length-filter / dedupe / sort / sort-by-length /
  split-to-zip). The long key sweeps and table generation
  (`pdf-keyattack`, `office-keyattack`, `thunder-gen`) instead build a
  copy-ready CLI command from a small form. Recovered secrets stay gated behind
  `--expose-secrets`, matching the crack path.
- **Web GUI, expanded.** `xcrack-web` gains: a dedicated **Configuration** view
  holding the YAML editor (with a "run from this YAML" toggle) and an
  **Appearance** theme picker (System / Light / Dark / Glow / Gold / Autumn /
  Spring, remembered per browser); an **Advanced** Crack form exposing the full
  engine surface in grouped panels, including a **Distributed cracking** panel
  that fans the search out to `xcrackd` servers via `cluster.Run` (gated to
  `--allow-server-paths`); **hover tooltips** on every setting; a client-side
  **wordlist preview**; a live **job panel** (start timestamp, elapsed clock,
  determinate/indeterminate progress bar, latest term tested, throughput); and
  **Statistics** additions — per-algorithm/cipher speed and a recovered-password
  top list. (`/stats` now reports `algo_speed` and `top_passwords`; progress
  events carry the keyspace and latest candidate.)
- **`thunder-gen --progress`.** The one-time Thunder Table build can now report
  periodic progress: `--progress N%` (N = 1, 5, 10, 25) prints each time that
  fraction of the planned chains is reached, or `--progress N<hour|day>` prints
  on that wall-clock cadence. Each line shows percent, chains done/total,
  elapsed and an ETA (`pdf.TableParams` gains a `Progress` callback). Both the
  CPU and `--gpu` paths are covered; generation speed is unaffected.
- **Security chapter in the user manual.** `docs/USERMANUAL.md` gains a dedicated
  Security chapter: the threat model, the security posture of `xcrack`,
  `xcrackd` and `xcrack-web`, how to enable TLS, and the TPM-sealed cache
  (moved from the web-GUI chapter).
- **Web GUI (`xcrack-web`).** A new single binary serves a browser front-end to
  the engine plus a JSON/SSE API (`pkg/webui`): drag-and-drop uploads, an
  easy-mode form and an **advanced mode** with an IDE-style YAML configuration
  editor (CodeMirror), a statistics dashboard with live throughput graphs
  (uPlot), decrypted-output download, and the full documentation rendered
  in-app. It runs locally (localhost, a single-user console) or as a service
  (TLS + reverse-proxy auth, like `xcrackd`). A submitted job may reference only
  the files uploaded with it unless `--allow-server-paths` is set.
- **One canonical job schema (`pkg/jobspec`).** The CLI `--config`, the
  embeddable library and the web editor now share a single `Spec` type and the
  one assembler that turns it into engine options + candidate sources, so a
  capability expressible in the YAML is reachable from every surface. The schema
  is extended to cover options that used to be CLI-flag-only (combinator,
  increment, PCFG/Markov tuning, min/max length, encoding, loopback, spray
  years, generate-rules, force-format, password files, GPU).
- **Optional TPM-sealed found-password cache (`-tags tpm`).** The found-password
  cache/potfile can be encrypted at rest with a key sealed to the host's TPM
  (`--cache-encryption tpm` / `output.cache_encryption: tpm`), so the file is
  useless if copied off the machine; tampering or a foreign key is detected and
  rejected. The default pure-Go build excludes the TPM dependency and reports a
  clear error if asked, keeping ADR 0001 intact. The plaintext cache is
  unchanged and remains the default.

### Documentation
- **Synced the docs to the implementation.** Brought the user-facing docs back
  in line with the code after the web-GUI build-out: the USERMANUAL web-GUI
  chapter (§10) now covers the two run modes, job history/durability, the
  recovered-password vault, the wordlist library, the attack wizard and mask
  builder, the rule tester, the cluster health check, the command palette and
  config sharing, and the full flag set; the security chapter and
  `architecture.md` describe `xcrackd`/`xcrack-web` as first-class network
  containers with the single-/multi-user posture; `API.md` lists the full
  `pkg/webui` endpoint set. The reference docs (`USAGE.md`, `FILEFORMATS.md`,
  `FAQ.md`, `CRACKING.md`, `TERMINOLOGY.md`) were reviewed against the registry
  and the CLI and corrected where they had drifted
  (e.g. the Ethereum-keystore format and KeePass KDBX3.1 are now listed as
  supported; the `hashline` emitter no longer claims a non-existent `$dmg$`
  line; ODF AES-256-GCM and encrypted DMG/KeePass are no longer shown as
  unimplemented; GPU/OpenCL is described as an opt-in build tier, not "out of
  scope").

### Removed
- **Dropped the dead `find_all` toggle.** `Options.FindAll` was reserved and
  never read by the engine, which already searches every encrypted node in the
  tree — so the `--find-all` flag, the `find_all` config key, the
  `Options.FindAll` field and the web-GUI "Find-all" checkbox had no effect.
  Removed all of them rather than leave a misleading knob; full-tree exploration
  stays the default and is unchanged.

### Fixed / performance
- **Third-party archive-parser allocation DoS hardening (7z + RAR).** The
  KDF/allocation sweep above covered Xcrack's own parsers; this follow-up audited
  the two bundled C-library ports that parse untrusted archive headers,
  `bodgit/sevenzip` and `nwaples/rardecode/v2`, for the same unbounded-allocation
  class.
  - **7z (`bodgit/sevenzip`): unbounded.** Header count fields (file/stream/
    folder/coder counts) are capped only at `MaxUint32`, never against the
    archive length, so a ~40-byte crafted archive can drive a single
    `make([]FileHeader, 4.29e9)` ≈ 480 GiB (and several lesser multi-GiB
    allocations). The engine's `recover()` guard does not help: an allocation
    that large does not panic — the Go runtime instead throws a fatal,
    unrecoverable out-of-memory. Added a bounded, size-proportional header
    pre-scan (`szWithinSize`, `sevenzip_guard.go`) that every 7z open now passes
    through; it mirrors the library's header grammar far enough to reject any
    count that exceeds the file size — provably impossible for a real archive, so
    no valid archive is turned away — on the plaintext-header path and in the
    outer StreamsInfo of an encoded header. Residual: the *inner* metadata of an
    encoded (compressed) header is decompressed by the library before it is
    parsed, so its counts remain out of reach of a size-based outer gate; fully
    closing that needs an upstream proportionality fix or OS-level memory
    isolation for untrusted-upload deployments (see docs/threat-model.md).
  - **RAR (`nwaples/rardecode/v2`): bounded parse, one capped window.** The
    block/header parse is input-proportional, but the decode-window buffer is
    sized from a header dictionary-size field and allocated during enumeration up
    to the library default of 4 GiB from a tiny file. All RAR readers are now
    built with `MaxDictionarySize(maxDecompressed)` (1 GiB, matching the per-
    stream read backstop — Xcrack never reads more than that from an entry), cutting
    the worst-case window from 4 GiB to 1 GiB with no functional loss.
  - Adds a crafted-oversize-header regression test and a `FuzzEntries` seed for
    the 7z vector, and an invariant test that the RAR cap stays below the library
    default.
- **Parser KDF-cost/allocation DoS hardening (sweep prompted by the RAR5 fix).**
  An audit of every scheme for the same bug class — an untrusted header value
  driving a KDF/hash loop or an allocation without an upper bound — found and
  capped several more. All are reachable from the engine's Detect→Probe→Verify
  path, and the KDF loops take no context, so a hang can't be cancelled; the cap
  at parse/verify is the mitigation:
  - **ethkeystore** — `dklen` was lower-bounded only; a huge value both allocated
    and multiplied PBKDF2 cost. Capped (`maxDKLen`). Also added a scrypt working-
    set ceiling (`128·N·r`), since the per-parameter caps still allowed tens of
    GiB.
  - **dmg** — the `encrcdsa`/`$dmg$` PBKDF2 iteration count (a uint32) was
    unbounded. Capped at `maxIterations` (1<<24).
  - **p12** — the PKCS#12 MacData iteration count (ASN.1 INTEGER) was unbounded.
    Capped at `maxMacIterations` (1<<24).
  - **privkey** — PBES2 PBKDF2 iterations and scrypt `N/r/p` were unbounded.
    Capped (iterations 1<<24; scrypt N≤1<<20 with a `128·N·r` ceiling).
  - **puttykey** — `.ppk` v3 Argon2 `Memory` (KiB) and `Passes` were unbounded
    (OOM / hang). Capped, mirroring the keepass bounds; parallelism must be >0.
  - **ooxml** — agile `KeyBits` was unbounded, forcing large per-candidate key-
    buffer allocations before the cipher rejected the size. Bounded (`maxKeyBits`).
  - **sshkey** — the bcrypt-pbkdf `rounds` field was never validated; safe today
    only because the pinned `x/crypto` caps it, so a cap is now enforced at parse
    (`maxRounds`) independent of the dependency version.
  Adds scheme-level regression tests for the ethkeystore and dmg caps. Already-
  bounded schemes (rar5, keepass, age, iwork, odf, ooxml spinCount, pgp, …) were
  confirmed correct and unchanged.
- **RAR5 KDF-cost denial of service fixed (found by nightly fuzzing).** A RAR5
  crypt header stores its PBKDF2 iteration count as a one-byte base-2 logarithm,
  which `parseRAR5CryptRecord` accepted unchecked. A corrupt or hostile header
  claiming e.g. `lg2=48` drove the fast password verifier (`rar5.PswCheckValue`)
  to ~2^48 HMAC-SHA256 rounds — an effectively infinite hang on any RAR5 input,
  reachable from the archive `FuzzEntries` target (it surfaced there as a
  "fuzzing process hung" failure). The exponent is now capped at `MaxLg2Count`
  (24, matching WinRAR/UnRAR's `CRYPT5_KDF_LG2_COUNT_MAX` and the rardecode
  decoder): the parser refuses an out-of-range record (falling back to the
  decoder, which rejects it too) and `rar5.Verify` returns false instead of
  running the loop. Adds a scheme-level regression test and commits the fuzzer's
  crashing input as a `FuzzEntries` seed.
- **7z content-encryption detection and password check are now deterministic.**
  A content-encrypted 7z (`7z a -p`, plaintext headers) could intermittently be
  read as plaintext, or a wrong password accepted: 7z has no password MAC, the
  `bodgit/sevenzip` library does not validate the per-member CRC on read, and the
  detector probed by reading a single byte — so whether a wrong-password garbage
  stream "decoded" without error depended on the archive's random AES IV. This
  surfaced as a flaky `TestEncrypted7zEngine` under `-race`. The detector and the
  password verifier now recompute the member's stored **CRC32** over the decoded
  bytes and require a match (falling back to "decoded cleanly" only when no CRC is
  stored or the member exceeds the decompression backstop), making both
  IV-independent. Added a regression test over 30 fresh tiny archives.
- **`xcrack-web` job progress finalises cleanly.** The indeterminate progress
  bar kept sweeping forever after a run ended (it re-added the animation on the
  final update); it is now tied to the live event stream and stops when the run
  finishes. The progress panel gained an **Ended** timestamp alongside Started/
  Elapsed, and the results now lead with an **"X of Y decrypted"** summary.
- **`xcrack-web` single-user mode no longer shows a login gate.** The full-screen
  login overlay (`.login-gate`) was styled `display:flex` with no `[hidden]`
  rule, so the `hidden` attribute — and the `hidden=true` the SPA sets in
  single-user mode and once signed in — was overridden and the gate covered the
  app anyway, prompting a sign-in whose button hit `/auth/login` and returned
  `authentication is not configured`. Added the `.login-gate[hidden]` guard (as
  `.modal[hidden]` already has) and a regression test over the embedded asset.
- **`xcrack-web` drains in-flight jobs on shutdown (fixes a flaky test).** A job
  runs in a background goroutine that outlives its `202 Accepted` response, so
  nothing waited for it: on `SIGINT`/`SIGTERM` the server stopped HTTP but
  abandoned running jobs mid-write, and in tests a runner could still be writing
  under the `t.TempDir()` work directory as it was removed — an intermittent
  `RemoveAll … directory not empty` failure in `pkg/webui`. The job `Manager`
  now tracks its runner goroutines and gains `Shutdown()` (exposed as
  `Server.Close()`) that cancels every in-flight job and waits for the
  goroutines to exit; `xcrack-web` calls it after the HTTP shutdown, and the
  test server drains jobs before its work directory is cleaned up.
- **`thunder-gen --gpu` column-batched chain kernel (occupancy).** The GPU
  thunder-chain walk previously ran one work-item per chain over the *whole*
  chain length in a single dispatch, which forced a dilemma on integrated GPUs:
  a long dispatch trips the compute watchdog ("ring timeout" / "context lost" →
  GPU reset), so the chain count per submission had to be capped low enough that
  `chains × ChainLen` stayed under the watchdog — which left the device's lanes
  under-occupied and the iGPU no faster than the CPU. The kernel is now
  **column-batched**: each device holds its chains as a device-resident bank of
  running keys and advances them only a few columns per dispatch, so the host can
  launch the *full* chain width of work-items (high occupancy) while each
  submission's op-work stays under the watchdog regardless of `ChainLen`. The two
  knobs are now separated: `--gpu-batch N` / `XCRACK_GPU_CHAIN_BATCH` sizes how
  many chains are offloaded per call (occupancy; a wide default keeps the lanes
  full), and the new **`XCRACK_GPU_OP_BUDGET`** bounds a single submission's
  work-items × columns (default `2^24`) — lower it if a device still trips its
  watchdog, raise it for more throughput headroom. The column sweep is
  byte-identical to the single-dispatch walk and the pure-Go reference, validated
  by the GPU-vs-CPU self-test and the `thunder-gen` GPU integration test
  (including the multi-column resume path).
- **`thunder-gen` plan estimates are honest for small `--bits`.** The plan's
  "chain work", wall-clock and on-disk-size lines counted the full `--chains`
  per sub-table even when the key space is smaller, over-stating a `--bits 24`
  build by ~4× (e.g. "1.1T ops / 2.5 GiB"). They now cap chains per sub-table to
  the key space (`min(--chains, 2^bits)`, matching generation) and note the cap;
  the wall-clock is labelled a **CPU** estimate (it never reflected `--gpu`, and
  under `--gpu` the line now points to the live progress for the real rate).
- **`thunder-gen --gpu` self-tests the kernel and shows progress.** Before
  trusting a device for the whole table, `thunder-gen --gpu` now runs the GPU
  self-test (which validates the thunder-chain generator against the CPU
  reference) and falls back to the CPU on any mismatch — a miscomputing kernel
  can no longer silently produce a corrupt table, since a thunder endpoint is
  not re-checked anywhere later. The offloaded chain walk is also swept in
  bounded chunks so `--progress` advances *during* each sub-table instead of
  only at its 25% boundaries (and peak host memory per offload call is bounded);
  a chunk error still falls the whole sub-table back to the CPU walk, now
  without double-counting progress. Each offload call is also sized to a bounded
  image-op budget (≈ `chains × ChainLen`) so a single GPU submission stays well
  under the device's compute watchdog — a too-large dispatch otherwise trips a
  "ring timeout" / "context lost" and the driver resets the queue (seen on
  integrated GPUs). `--gpu-batch N` / `XCRACK_GPU_CHAIN_BATCH` overrides the
  per-submission chain count when a device needs a smaller one.
- **Thunder Tables usable by default + parallel lookup.** The shipped
  `thunder-gen` default chain length was `2^20`, which made a V1/R2 lookup cost
  ~`tables×t²/2 ≈ 2^41` RC4 image ops — *slower* than the `2^40` brute-force
  sweep it replaces. The default is rebalanced (`--length 4096`, `--chains 2^26`)
  so lookup is seconds, not slower-than-brute-force, and `Table.Lookup` now
  parallelises the column scan across cores. `ReadTable` no longer pre-allocates
  from an attacker-controlled chain count (a crafted `--table` claiming ~4.3e9
  chains forced a ~64 GB alloc / OOM); it grows as bytes are read and fails fast
  on a truncated stream. Chain generation checks for Ctrl-C on an op budget
  (~`2^20` ops) instead of every 4096 chains, so cancellation is prompt at large
  chain lengths. The `--dry-run` time estimate no longer overflows int64 for very
  large plans. The "sub-second" claim is corrected to "seconds".
- **GPU key attacks fall back and stay complete.** `pdf-keyattack`/`office-keyattack`
  now fall back to the CPU for the current and remaining keyspace on a mid-sweep
  GPU error (instead of aborting the whole attack), and on a device false positive
  they re-sweep that chunk on the CPU rather than skipping past a real key that
  may sit later in it.
- **`--reuse-output` stamp no longer corrupts passwords** containing a newline:
  recovered passwords are quoted in the `.xcrack-stamp` so they round-trip exactly.
- **zstd codec**: dropped a dead "validate up front" decoder that read nothing
  (a malformed stream already surfaces on first Read), matching the lz4 codec.

### Added
- **Library/REST parity, an API reference, a bigger manual, and embedding
  examples.** `xcrackd` now exposes the same engine knobs as the CLI as flags —
  `--batch-size`, `--throttle`, `--no-recurse`, `--explode-documents`,
  `--context`, `--hint`, and the `--max-depth`/`--max-nodes`/`--max-total-bytes`/
  `--max-entry-size`/`--max-candidates` limits — so an operator configures the
  server engine exactly as the local engine (the library already mirrored the CLI
  via `Options`). New [`docs/API.md`](API.md) documents the embeddable library
  (`Pool`/`Process`, every `Options` field, candidate sources, results and
  callbacks) and the REST API (`xcrackd` flags, endpoints, request shapes and the
  JSON report), and explains the parity model (the controller generates
  candidates; the server is a stateless verify/KDF worker). The user manual gained
  a **CLI reference** chapter (every subcommand and flag family), an **Embedding
  the library** chapter, and much richer distributed/GPU and advanced-usage
  sections with many more worked examples. Five new runnable embedding examples
  join `impex-embed`: `batch-triage`, `candidate-pipeline`, `pin-fastreject`,
  `inspect-tree` and `http-service` (indexed in
  [`xcrack/examples/README.md`](../xcrack/examples/README.md)).
- **TLS for the REST API and the distributed client.** `xcrackd` can now
  terminate HTTPS itself: `--tls-cert`/`--tls-key` serve TLS (1.2 floor, or
  `--tls-min-version 1.3`), and `--tls-client-ca` turns on **mutual TLS**
  (client certificates required and verified against a CA bundle). The `xcrack`
  distributed client gained matching flags for `https://` servers: `--tls-ca`
  (trust a private/self-signed server cert), `--tls-cert`/`--tls-key` (present a
  client cert for mTLS), `--tls-server-name` (SNI/verification override) and
  `--tls-insecure` (skip verification — testing only, with a loud warning); the
  same settings live under `cluster.tls.*` in a config file. Two helper scripts
  create the certificates: `scripts/gen-selfsigned-cert.sh` (a self-signed server
  cert with SANs, or a full CA + server + client mTLS kit) and
  `scripts/gen-letsencrypt-cert.sh` (a certbot/ACME wrapper for a public
  endpoint). Verified end to end — `xcrackd` over HTTPS cracking for the `xcrack`
  client that trusts its cert — plus unit tests for the server/client TLS config
  builders and an HTTPS round-trip test.
- **Dual CPU+GPU parallel pipeline (`--dual-pipeline`).** For an
  acceleration-capable target, the CPU search and the GPU sweep now run
  **concurrently over one shared, de-duplicated candidate stream** instead of the
  CPU sitting idle while the device works: a new `sharedFeeder` serializes the
  keyspace so each candidate is tested on exactly one lane, and the **first lane
  to find the password cancels the other** (both then advance to the next file).
  A password near the front of the stream is found by the CPU without waiting for
  a device batch, while the device chews through the bulk — so the pipeline is a
  speed change, never a result change (cross-validated against the sequential
  path). The device's hits are still re-checked on the CPU, and if the device
  cannot serve the parameters mid-race it re-verifies its pending batch on the CPU
  (no candidate is lost) and hands the rest of the sweep to the CPU lane. Exposed
  as `Options.DualPipeline`, `xcrack --dual-pipeline` (with a new `xcrack --gpu`
  that attaches the OpenCL tier to the live crack loop, mirroring `xcrackd`), and
  `xcrackd --dual-pipeline`. Opt-in; inert without an active GPU tier; default
  build stays pure-Go (ADR 0001). Tested end to end with the pure-Go stub
  accelerator (de-dup, hit parity, no-false-positive, and device-failure
  fallback) under `-race`.
- **Syslog + structured audit logging (CLI and `xcrackd`).** A new
  `pkg/auditlog` package builds one `log/slog`-backed logger for both tools with
  `--log-level`, `--log-format text|json`, an optional `--log-file`, and a
  `--syslog` backend (`--syslog-address`/`--syslog-network` for a remote sink,
  `--syslog-tag`), so the whole run — the engine's diagnostics and the audit
  trail — can be followed in one place. Every processed source emits an audit
  record; a successful recovery is logged at info as **"file cracked"** with the
  **filename, file type, time-to-crack** and cracked entries, and a per-node
  debug trace lets the full execution be followed at `--log-level debug`. The
  **recovered password is logged only with `--audit-log-password`** (off by
  default, so the trail stays secrets-free). The engine gained a per-node
  `Node.CrackDuration` (per-node time-to-crack), an opt-in
  `Options.AuditIncludeSecrets`, and `Node.AuditEvent`; `xcrackd` serves the
  same trail per request (client, endpoint, bytes, elapsed) via the new
  `api.Config.Audit` hook. The syslog backend is Unix-only (guarded by build
  tags; `--syslog` is a clean error elsewhere) and the default build stays
  pure-Go (ADR 0001).
- **GPU-accelerated Thunder-Table generation.** `xcrack thunder-gen --gpu`
  offloads the rainbow-chain walk — the heavy one-time cost of building the PDF
  V1/R2 TMTO — to an OpenCL device via the new `pdf_thunderchain` kernel (one
  work-item per chain) and the `pdf.ChainComputer` seam / `accel.PDFThunderChainer`
  capability. The GPU chain is **byte-identical** to the pure-Go walk (same R2
  image, same column/seed reduction with the power-of-two mask), so a GPU-built
  table is inverted by the same CPU lookup — cross-validated GPU-vs-CPU
  byte-for-byte in `thundergen_opencl_test.go`, plus a `GPUSelfTest` chain case.
  `GenerateTable` falls back to the CPU walk per sub-table on any device error,
  so the offload never corrupts a table. Default build stays pure-Go (ADR 0001);
  ships only with `-tags opencl`, and `--gpu` degrades to CPU when unavailable.
- **Precomputed "Thunder Tables" (rainbow TMTO) for PDF V1/R2.** `xcrack
  thunder-gen` builds a rainbow time-memory trade-off and `xcrack pdf-keyattack
  --table FILE` inverts the R2 user-verifier `/U = RC4(fileKey, pad)` → 40-bit
  file key in sub-second, replacing the ~week-of-CPU 2^40 sweep. Because R2 `/U`
  is a salt- and ID-free function of the key, one table inverts every V1/R2
  document — the capability Elcomsoft markets as "Thunder Tables"
  (`xcrypto/scheme/pdf/thundertable.go`: column-indexed rainbow chains, multiple
  independent sub-tables for coverage, compact 5-byte-key binary store, parallel
  cancellable generation). Every lookup hit is re-checked against the real `/U`
  and `VerifyFileKey`, so a chain false-alarm is rejected and the table never
  yields a wrong key; a miss (or an R3/R4 / Office file, which are per-document
  and not cross-file-invertible) falls back to the live sweep. `thunder-gen
  --dry-run` estimates the generation work/size/time. Cross-validated in
  `thundertable_test.go` (coverage, exact correctness vs. `VerifyFileKey` and the
  live `RC4KeyAttack`, serialization round-trip, false-alarm rejection).

### Changed
- **Embedded dictionaries moved to `xcrypto/candidates/dictionaries/`.** The
  shipped Swedish wordlist is now `dictionaries/swedish.txt` (embed path and the
  `gen_swedish.go` regenerate command updated); the new directory has a README
  and is the home for future embedded, locale-specific lists. No behaviour
  change — `--swedish` works exactly as before.

### Added
- **GPU kernel: VBA project salted-SHA-1 batch.** The MS VBA project-protection
  verifier — `PasswordHash = SHA1(password‖salt)` with a 4-byte salt, hashcat's
  `sha1($pass.$salt)` (mode 110) — now offloads to an OpenCL device through the
  live crack loop (`xcrackd --gpu`), the same path the PBKDF2/Office-spin batches
  use. `kernel_vba_sha1.cl` bulk-hashes a whole candidate batch per dispatch; the
  new `accel.SaltedSHA1Hasher` capability and an `AccelKDF.SaltedSHA1` seam drive
  it (the VBA format now implements `xfileformats.Accelerable`). Because the hash
  is cheap and un-iterated, the `Finish` closure trusts only a device non-match (a
  byte compare) and re-hashes on the CPU (`vbaproject.Verify`) for an apparent hit,
  so the device never decides correctness; it falls back to the per-candidate CPU
  hash when no device is built/available. Validated on pocl against `crypto/sha1`
  — `GPUSelfTest` gains a salted-SHA-1 case, plus a kernel cross-validation test
  and a `-tags opencl` end-to-end engine test over a committed VBA fixture.
  Default build stays pure-Go (ADR 0001); ships only with `-tags opencl`.
- **GPU kernel: PDF 40-bit RC4 file-key search.** The second key-SEARCH OpenCL
  kernel: `pdf-keyattack --gpu` offloads the PDF Standard Security Handler's 2^40
  file-key sweep (V1/R2 and 40-bit R3/R4) to an OpenCL device. Because the file
  key is `MD5(…)[:5]` and `/U` is a function of that 5-byte key alone,
  `kernel_pdf_rc4keysearch.cl` is **RC4-only** — the one per-document MD5 the R3/R4
  path needs (`MD5(pad‖ID)`) is constant across keys and precomputed on the host
  (`pdf.Handler.RC4KeyAttackParams`), so each work-item just RC4s the input
  `rounds` times (round `r` keyed by `key5 XOR r`) and compares to `/U`. It reuses
  the MD5+RC4 cores and the hit/atomic plumbing of the Office sweep. The new
  `accel.PDFRC4KeySearcher` capability drives it, with transparent CPU fallback
  (`pdf.Handler.RC4KeyAttack`) and an authoritative CPU re-check of any hit
  (`pdf.Handler.VerifyFileKey`). Validated on pocl against the CPU reference —
  `GPUSelfTest` gains R2 and R3/R4 cases, plus a kernel cross-validation test and a
  `-tags opencl` end-to-end CLI test. Default build stays pure-Go (ADR 0001); ships
  only with `-tags opencl`.
- **GPU kernel: Office 97/2000 40-bit MD5+RC4 key search.** The first key-SEARCH
  OpenCL kernel (distinct from the per-password PBKDF2/Office-spin batch kernels):
  `office-keyattack --gpu` offloads the 2^40 trunc sweep (the Elcomsoft "Thunder
  Tables" / hashcat thread-3665 attack) to an OpenCL device. `kernel_oldoffice_
  md5rc4.cl` does MD5 + RC4 per trunc index on the device; the new
  `accel.OldOfficeKeySearcher` capability drives it, with transparent CPU fallback
  and an authoritative CPU re-check (`officebinary.VerifyRC4Trunc`) of any hit.
  Validated on pocl against the CPU reference (`officebinary.RC4KeyAttack`) —
  `GPUSelfTest` gains an oldoffice case, plus a kernel cross-validation test and a
  `-tags opencl` end-to-end CLI test. Default build stays pure-Go (ADR 0001);
  ships only with `-tags opencl`. PDF R2–R4 (same key-search shape) shipped as the
  follow-up above.
- **CLI parity features (basic/intermediate gap review).**
  - `-1/-2/-3/-4` (`--custom-charset1..4`): command-line mask custom charsets
    `?1..?4` (hashcat `-1..-4`), used by `--hcmask`/`--pattern` masks.
  - `--generate-rules N` (`--generate-rules-seed S`): fold N reproducible random
    mangling rules into the rule pool (hashcat `-g`); `pattern.GenerateRules`
    emits only rules that compile.
  - `xcrack wordlist`: wordlist maintenance (hashcat-utils niche) — `--dedupe`,
    `--sort`/`--sort-length`, `--min-length`/`--max-length`, `--split N`.
  - `--outfile-format LIST`: found-password line format for `--results-file`/
    stdout (1=target, 2=plain, 3=hex-plain).
  - `--status-timer N`: a files-done/elapsed heartbeat every N seconds.
- **`--reuse-output` output result cache.** With `-o`, record each source's
  content hash + candidate signature + recovered passwords in a per-output
  `.xcrack-stamp`, and on a repeat run skip any still-valid source entirely — no
  verification KDF, no decrypt, no decompose, no rewrite. This is the gap behind
  "why isn't a cached re-run instant?": `--found-cache` only *orders* candidates
  (so the known password is tried first, skipping wrong-guess KDFs) but still
  re-verifies and re-extracts every run; `--reuse-output` skips the file. A warm
  `--reuse-output -o DIR samples/*` run drops from ~18s to ~0.02s.
- **MS VBA project password recovery (MS-OVBA).** `xcrack vba-recover FILE` and
  `--as vbaproject` recover the VBA IDE "lock project for viewing" password from
  the DPB field of the VBA `PROJECT` stream (MS-OVBA 2.4.3 reversible Data
  Encryption). A plaintext password is read out with no cracking; a hashed one is
  `SHA1(password‖4-byte salt)` — a fast salted-SHA-1 verifier crackable in-engine
  (`--as vbaproject`) or via the emitted John `dynamic_24` / hashcat `-m 110
  --hex-salt` lines. Works on legacy `.doc/.xls/.ppt`, a standalone
  `vbaProject.bin`, and OOXML `.docm/.xlsm/.pptm` (the `word/vbaProject.bin` part
  is unwrapped). New `xcrypto/scheme/vbaproject` (transform round-trip tested,
  salted-SHA-1 cross-validated against an independent MS-OVBA + hashlib reference
  over golden fixtures incl. NUL-byte key/hash cases) and
  `xfileformats/formats/vbaproject` (force-only; parsers fuzzed). The VBA source
  is never encrypted, so only the password is the deliverable.
- **Codecs: zstd & lz4 containers.** Two single-stream compressors are registered
  as containers (`xfileformats/formats/archive/codec.go`), so a password-protected
  file wrapped in a modern codec — most importantly `.tar.zst` / `.tar.lz4`, where
  the inner tar and any encrypted file in it were previously unreachable — is
  decompressed and recursed into like gzip/bzip2/xz. Pure-Go decoders already in
  the module (`klauspost/compress/zstd`, `pierrec/lz4/v4`, now promoted to direct
  requires), so the cgo-free default build is unaffected; output is bounded by
  `maxDecompressed` and the engine budgets, and decode errors surface as
  recovered-so-far / `ErrMalformed`, never a panic. zstd detection also covers
  skippable frames. Tested by round-trip + a `.tar.zst` recursion test and an
  end-to-end engine test that cracks a WinZip-AES entry inside a `.tar.zst`.
- **GPU kernel: Office 2010+ agile iterated-hash spin.** A new OpenCL kernel
  (SHA-1/256/384/512) runs the ~100k-iteration spin that dominates every modern
  Office document's key derivation — the single biggest per-candidate cost for
  encrypted OOXML. It is not a PBKDF2: the CPU does the one variable-length first
  hash `H(salt‖UTF16LE(pw))` and the device runs the fixed-size loop
  `cur = H(LE32(i)‖cur)` (a new optional `accel.OfficeHasher` capability and
  `AccelKDF.Office` seam; ooxml exposes it via `AccelKDF`, with `Finish` running
  the authoritative agile verifier on the device-derived digest). Byte-for-byte
  self-tested against `prim.OfficeAgileHash` for all four hashes at startup and
  validated end-to-end through the engine against pocl (`TestOpenCLOfficeAgileLive`)
  and with a pure-Go stub in the default build (`TestAccelOfficeAgile`). The spin
  kernel is shared with Office 2007 "standard"; only that scheme's post-spin
  `Finish` wiring remains.
- **GPU acceleration for ODF and RAR5.** The opt-in OpenCL tier already shipped
  PBKDF2-HMAC-SHA1/256/512 kernels but only WinZip-AES and encrypted DMG were
  wired to them. Now **ODF** offloads its PBKDF2-HMAC-SHA1 content-key spin (via
  a new `AccelKDF.PreHash` field that applies ODF's SHA-256/SHA-1 start-key hash
  to each candidate on the CPU before the kernel), and **RAR5** offloads its
  PBKDF2-HMAC-SHA256 password-check derivation (the 8-byte check value is a fold
  of `PBKDF2-HMAC-SHA256(pw, salt, 2^Lg2Count+32, 32)`). Both validated against
  pocl end-to-end through the engine, with the CPU verifier re-checking every
  hit. SQLCipher is deliberately left on the CPU (its v3/v4 profile is unknown
  before a password verifies, and the seam derives one profile per candidate).
  New scheme helpers: `odf.VerifyWithKey`/`DecryptCompressedWithKey`/
  `AccelStartHash`, `rar5.PswCheckFromDK`/`VerifyDK`/`AccelIterations`.
- **`--show-config`** — print the effective configuration (flags + env + config
  file + defaults, merged, with precedence noted) and exit without cracking. It
  shows counts for explicit passwords and the cache path, never secret values,
  so it is safe to paste into a bug report.
- **`--show-cache`** — list the passwords held in the found-password cache /
  potfile and exit (needs `--found-cache`/`--remember`/`--potfile`). Distinct
  from `--show`, which reports which *files* the cache solves.
- **`--extract-suffix S`** (config `output.extract_suffix`) — change the
  per-source extracted-tree directory suffix under `--out` (default
  `.extracted`; `''` = the bare source name). Validated as a single path segment
  (no `/` or `..`) so it can never redirect the write outside `--out`.

### Tests
- **Regression tests for the parser cost/size DoS caps + a `make cover` target.**
  Added dedicated guard tests for every KDF-cost / allocation cap, each with a
  positive control so it can't pass vacuously: `rar5` (lg2 exponent), `dmg` and
  `ethkeystore` (iteration count / dklen / scrypt working set), and parse-level
  rejection for `p12` (MacData iterations), `privkey` (PBES2 PBKDF2 iters +
  scrypt N/r/p), `puttykey` (Argon2 memory/passes) and `sshkey` (bcrypt rounds).
  New `make cover` measures per-module statement coverage (it enumerates only
  packages with tests, so a no-test package can't break the run on a downloaded
  Go toolchain); `coverage.out` is git-ignored.
- **`gold/` cross-validation fixture index.** A top-level `gold/README.md` records
  the provenance (source tool/version or spec, licence, known answer, in-repo
  path) of every externally-sourced cross-validation fixture, so cross-validation
  survives the source moving/disappearing; fixtures stay committed in-tree with a
  per-directory `ATTRIBUTION.md`. Committed `gold/vba/vba_oracle.py` (the MS-OVBA
  reference generator for the VBA DPB fixtures, previously output-only; verified
  to reproduce them). Filled two missing `ATTRIBUTION.md` files (the qpdf PDFs and
  the header-encrypted `hdr.7z`/`hdr.rar`).

### Docs
- **New [`USERMANUAL.md`](USERMANUAL.md)** — a task-oriented user manual:
  introduction, how to use the tool, GPU acceleration, distributed environments,
  advanced usage, and debugging/troubleshooting. Linked as the start-here doc in
  both doc indexes.
- **New [`docs/Makefile`](Makefile)** — builds a combined printable PDF
  (`Xcrack-Manual.pdf`) and per-doc PDFs from the Markdown via pandoc + a PDF
  engine (`make check` reports tool availability; graceful error if absent).
- **TERMINOLOGY.md**: every table reordered strictly A–Z, and substantially
  expanded with more terms, abbreviations and TLAs across all sections (engine,
  KDFs, ciphers/modes, formats, attacks, acceleration, and the abbreviation
  index).
- **roadmap-enhancements.md**: folded in the 2026-10 competitor analysis
  (hashcat / John / Passware / Elcomsoft) and detailed the remaining format
  work — Java key stores (BKS/JCEKS), regional/legacy docs (HWP/HWPX,
  WordPerfect, Lotus 1-2-3), Apple images (`.sparseimage`/`.sparsebundle`,
  iOS/iTunes keybag), installers & disk images (MSI/CAB/NSIS/ISO/UDF/VHD(X)/IMG,
  with the note that all image/container parsers live in `xfileformats`), and
  more codecs (brotli/LZH/ARJ/ACE/SecureZIP, cpio, ar). Added items for
  precomputed Thunder Tables / rainbow tables for the 40-bit Office/PDF sweeps,
  a dual CPU+GPU parallel-pipeline (per-file race), broadening the GPU tier, and
  the net-new competitor gaps (key-from-memory/recovery-key decryption, a
  forensic GUI/reporting layer, managed cloud-burst/agent orchestration).
- **New [`PERFORMANCE.md`](PERFORMANCE.md)** — per-format KDF cost model, measured
  single-box CPU verify rates (`xcrack --benchmark` on a 4-core Xeon), attack-method
  effort, the 40-bit key-sweep rate, and CPU / distributed / GPU scaling.
- **New [`TESTS.md`](TESTS.md)** — the test suite: counts, the external oracles each
  scheme is cross-validated against (with fixture locations), fuzzing, the
  hostile-input/budget tests, the `-tags opencl` GPU suite, and exactly what CI runs.
- **FAQ.md** gains a top-of-file topic index and new sections: terminology & basics,
  files and file types, keys and key lengths, cracking limitations, performance and
  cracking times, testing and validation, a documentation map, and kernel/core/
  OpenCL/pocl answers in the GPU section. Linked from both doc indexes.
- **Mermaid attack-pipeline diagram** added to README.md ("How it works") and
  docs/CRACKING.md §1 (replacing the ASCII sketch): detect → probe → candidate
  stream → fast-reject → verify → decrypt → re-detect, with the opt-in GPU tier
  and the verification-shortcut branch shown. (Diamond labels shortened so GitHub's
  renderer no longer clips them.)
- FAQ: explain why a cached re-run isn't instant (candidate-ordering vs result
  cache) and point to `--reuse-output`; USAGE documents the new flags.
- CRACKING.md §3 + REFERENCES.md: record hashcat forum **thread-3665**
  ("Colliding password protected MS office 97-2003 documents") as the canonical
  reference for the Office 97/2000 40-bit MD5+RC4 key attack Xcrack already ships
  as `office-keyattack` — its collider `-m 9710` opens the document without the
  real password, `-m 9720` finds the password, and SHA1+RC4 CryptoAPI is the
  separate `-m 9800` (correctly out of scope). VBA documented across CRACKING.md
  (§2 table + §3), FILEFORMATS.md, FAQ.md, TERMINOLOGY.md (VBA/DPB/MBCS) and
  roadmap-enhancements.md; MS-OVBA + Didier Stevens added to REFERENCES.md §8.
- README: add the `docs/CRACKING.md` and `docs/FAQ.md` references to the
  documentation index; correct the MS Access rows now that Jet `.mdb` recovery
  ships (ACE `.accdb` recovery remains staged).
- USAGE: a new **Use cases** section mapping nine end-to-end scenarios
  (malware triage, DFIR batch, forgotten password, pentest, no-crack recoveries,
  GPU offload, distributed, service, inspect-first) to commands; document
  `--extract-suffix`, `--show-config`, `--show-cache`.
- FAQ: new **Output & extracted files** and **Inspecting & troubleshooting**
  categories, plus entries for the new flags, formats, logging and exit codes.
- FAQ: new **GPU acceleration** category — what the device does vs. the CPU, the
  accelerated-formats table, why a scheme stays on the CPU (memory-hard /
  ambiguous profile / no kernel yet), multi-device selection, and the
  no-false-positive guarantee.
- CRACKING.md §3: record a fresh cryptanalysis survey of every supported format.
  Net outcome — the formats are already well covered; the notable additions are
  (a) a precise refutation of the common claim that Office **XP/2003 CryptoAPI**
  40-bit RC4 is key-attackable (each block key derives from the 160-bit
  `SHA1(salt‖pw)`, so recovering the 40-bit verifier key decrypts only block 0,
  not the document), (b) making explicit that the empty-**user**-password key
  derivation already decrypts owner-only PDFs of *every* revision (128-bit RC4
  and AES included — the only feasible route there), and (c) documenting the Wu
  2005 RC4 keystream-reuse weakness and the pure-Go ZipCrypto password recovery
  as known-but-not-built, with reasons.
- CRACKING.md §3 + REFERENCES.md: from two further Elcomsoft posts (legacy-ZIP
  known-plaintext; the history of PDF insecurity) — document the **Stay 2001**
  ZipCrypto results (reduced 2–3-byte known-plaintext, and the weak-RNG
  "guaranteed recovery" against WinZip ≤ 8.0 / NetZip with ≥ 5 entries) as staged,
  with reasons (recovered keys already suffice; no obtainable oracle for the
  weak-RNG tail); and record that PDF **R5** (Acrobat 9 AESV3) verifies with a
  **single SHA-256**, cheaper per guess than the iterated R6 — a property Xcrack's
  R5 verifier already has (`hash2B` short-circuits for `R < 6`).
- Roadmap: mark **Document explosion** (`--explode-documents`, ADR 0007) done, and
  add zstd/lz4 to the archive-unpackers entry; `roadmap-enhancements.md` marks the
  zstd/lz4 codecs shipped and splits out the remaining codecs / container parsers
  (brotli, cpio, ar, CAB, ISO 9660/UDF).
- Terminology moved out of `docs/README.md` into a new, extensively expanded
  **docs/TERMINOLOGY.md** (engine concepts, KDFs & hashing, ciphers & modes,
  formats & key stores, attacks & cryptanalysis shortcuts, acceleration, and an
  abbreviations/TLA index), referenced from README.md and docs/README.md.

## PR #19 — 2026-10-17 — Staged cryptanalysis shortcuts: ZipCrypto cross-entry, PDF 40-bit RC4, Access Jet

### Added
- **ZipCrypto cross-entry key reuse** — every entry in a ZipCrypto archive
  shares one password-derived pre-header key state, so a single recovery unlocks
  the whole archive. `xcrack kp --decrypt … --zip ARCHIVE [--zip-out DIR]` seeds
  the recovered entry-start state (`zip.DecryptArchiveWithStart`) into every
  other entry and decrypts them all with no further search; each entry is
  independently CRC-re-validated and AES / non-ZipCrypto entries are skipped.
- **PDF 40-bit RC4 file-key attack** — `xcrack pdf-keyattack FILE`
  (`xcrypto/scheme/pdf.Handler.RC4KeyAttack`): the PDF file key is a single MD5
  truncated to 5 bytes, independent of the password's length, so the 2^40
  file-key space is swept directly against the `/U` verifier and recovered with
  no password, from the public `/U`, `/ID` and revision alone. Covers V1/R2 and
  40-bit R3/R4; the common R2 case runs an allocation-free inline-RC4 hot loop.
  Shardable (`--shard i/N`), parallel (`--workers`); 128-bit RC4 and the AES
  schemes are declined. Cross-validated against a real 40-bit PDF produced by
  qpdf (`keyattack_test.go`).
- **MS Access (Jet) header-XOR decode** — `xcrack access-recover FILE`
  (`xfileformats/formats/access.RecoverJetPassword`): Jet3/Jet4 (.mdb) store the
  database password XOR-obfuscated with fixed, public material (a 128-byte header
  mask, plus a creation-date-derived 4-byte mask on Jet4), so the password is
  read straight out of the header with no cracking. ACE (.accdb, Access 2007+)
  uses a real Office-style KDF and is declined. Cross-validated against jackcess
  (an independent implementation that produced a known-password Jet4 fixture)
  and fuzzed against hostile headers. This clears the last of the three
  cryptanalysis shortcuts that CRACKING.md §3 had staged.

### Fixed
- `resolveRange` (the `--shard`/`--start`/`--max` keyspace splitter) now takes
  the keyspace size explicitly, shared cleanly between the Office trunc sweep and
  the new PDF file-key sweep (both 2^40).

## PR #18 — 2026-10-17 — Found-password cache, session/potfile, basic+intermediate features, GPU vendors, CRACKING.md

### Added
- **Found-password cache** — `--found-cache FILE` / `--remember` (default
  `$XDG_DATA_HOME/xcrack/found.txt`): a persistent potfile whose passwords lead
  the candidate stream, so a reused password is recovered instantly on the next
  run. Priority passwords now lead the per-file stream, ahead of the generators.
- **Full-run session resume** (`--session FILE`): a multi-file batch records each
  file once fully searched (with any recovered passwords) and skips finished
  files on re-run — the batch-level complement to `--checkpoint`.
- **Potfile reporting** (`--show` / `--left`, hashcat): report which files the
  found-password cache already solves, without cracking.
- **Loopback** (`--loopback`): re-mangle the cached/pot recovered passwords
  through the rules, tried early.
- **Candidate length filter** (`--min-length` / `--max-length`) and **encoding**
  (`--encoding utf-8|latin1|utf-16le|utf-16be`).
- **.hcmask mask files** (`--hcmask`, config `patterns.hcmask`): per-line masks
  with inline `?1..?4` charsets.
- **Markov threshold / position-aware** — `--markov-threshold N` caps the
  per-position branching; `--markov-pos` trains and generates from a 2D
  (position-aware) Markov model.
- **Rule-file debugging** (`--debug-rules`): per-rule kept/rejected counts and
  sample transforms. Also fixed a `--pattern` DSL bug that silently dropped the
  identity (`:`) rule.
- **VelvetSweatshop / empty password** tried up front (read-only-recommended
  Excel, owner-only PDF) — zero-search recoveries.
- **Distributed resume / cross-run dedup** (`--cluster-session FILE`): resume a
  fleet run without re-shipping candidates already confirmed tried
  (`cluster.Options.ResumeOffsets`, a safe contiguous-completed offset).
- **GPU vendor-aware autodetect**: the OpenCL tier ranks and selects the best
  device across NVIDIA / AMD / Intel / Apple / APU (`accel.VendorArch`,
  `DeviceRank`, `XCRACK_GPU_DEVICE`); AMD GPUs and Ryzen APUs run through the
  OpenCL ICD. xcrackd logs the vendor family per device.
- New reference docs: **docs/CRACKING.md** (per-format attacks, verification
  shortcuts & cryptanalysis, GPU-kernel candidates) and **docs/FAQ.md**; a
  complete config-key reference in **config/README.md**.

### Performance
- The Office 97/2000 2^40 RC4 key-attack inner loop is now allocation-free
  (reused mixing buffer, stack RC4 state, value-array MD5): per-candidate heap
  allocations drop from ~4 to zero, removing the GC pressure that dominated a
  sustained sweep.

## PR #16–#17 — 2026-10-17 — Inspection modes, crypto wallets, KDBX3, Office 40-bit key attack, GPU SHA-256/512, multi-GPU, cost queue

### Added
- **Ethereum keystore wallets** (Web3 Secret Storage v3, the `ethwallet`
  format): scrypt / PBKDF2-HMAC-SHA256 key derivation verified by the
  Keccak-256 MAC, detected on the keystore JSON markers. Cross-validated against
  the two canonical geth test vectors (the pbkdf2 MAC is the verbatim published
  value; the scrypt MAC is reproduced identically by a pycryptodome oracle and
  the Go path).
- **Legacy KeePass KDBX3.1** passphrase recovery in the `keepass` scheme/format
  (AES-KDF + AES-256-CBC stream-start-bytes verifier), alongside the existing
  KDBX4. Cross-validated against a genuine KDBX3 fixture accepted by both
  KeePassXC 2.7.6 and pykeepass 4.2.0.
- **Office 97/2000 RC4 40-bit key attack** (`xcrack office-keyattack FILE`): the
  Elcomsoft "Thunder Tables" weakness — sweep the 2^40 trunc keyspace against the
  document verifier to recover the key regardless of password length/complexity
  (shardable with `--shard i/N`, parallel across cores, resumable). Office
  XP/2003 CryptoAPI RC4 is correctly excluded (160-bit intermediate). The
  `xcrypto/scheme/officebinary` verifier/searcher is cross-validated against the
  msoffcrypto-tool reference vector.
- **GPU PBKDF2-HMAC-SHA256 and -SHA512 kernels** in the opt-in OpenCL tier
  (RAR5-class and SQLCipher-v4-class), beyond the existing SHA-1. The
  `xfileformats.AccelKDF` seam gained a PRF selector and the engine dispatches to
  the matching kernel. Every variant is validated byte-for-byte against the Go
  reference at startup.
- **Multi-device OpenCL + batch-size autotune**: the GPU tier now builds a queue
  and kernel per device and splits a batch across devices concurrently, and
  autotunes the per-dispatch batch size (exposed via `accel.BatchTuner`, used by
  the engine; `Options.AccelBatch` overrides).
- **Automatic cost-aware recovery queue** (`--cost-queue`, config
  `search.cost_queue`): benchmark each input file's verify rate and attack the
  fastest/weakest schemes first across a pile of files.
- **Inspection / estimation modes** on the crack command (no cracking):
  `--stdout` prints the assembled candidate stream (hashcat `--stdout`);
  `--keyspace` prints the candidate keyspace size; `--benchmark`/`-b` measures
  the per-file verify rate (candidates/sec); `--estimate` combines keyspace ×
  rate into a time-to-crack. `--limit N` caps `--stdout`/`--keyspace`.
- `--progress` now shows a true percent and a candidate-rate ETA for a single
  target whose keyspace is known (e.g. a mask), falling back to the per-file
  reporter otherwise.

## PR #15 — 2026-10-17 — Distributed cracking, challenge/Markov/time-limit CLI, Swedish list, RAR5

### Added
- **Distributed cracking across many xcrackd servers** (`pkg/cluster`): xcrack
  orchestrates a fleet of workers over the HTTP API. *Collective* mode throws
  every server at one file on disjoint candidate batches (first hit wins, the
  rest are cancelled); *partition* mode splits servers into groups that take
  different files. Server set and allocation are settable from the command line
  (`--server URL[@GROUP]`, `--cluster-mode`, `--cluster-batch`,
  `--cluster-allow-defaults`, `--cluster-per-request`) or the config `cluster`
  block. A worker only ever reports whether a candidate it was handed worked, so
  it cannot inject a false positive. The `xcrackd` API gained a multipart
  request shape (`file` + `wordlist` parts), a server-side `shard=I/N`, and a
  `max-duration` hint.
- **Embedded Swedish-targeted wordlist** (`--swedish`, `candidates.Swedish`):
  ~31k curated, language-specific entries (common words, names, cities, clubs,
  holidays + typical mutations), ordered most-probable-first, generated
  reproducibly by `gen_swedish.go`.
- **Challenge-envelope CLI**: `xcrack export-challenge` emits the portable JSON
  challenge envelope for an external cracker; `xcrack --resume-from` imports a
  recovered-password envelope and tries it first. (Previously the envelope was a
  library-only capability.)
- **Markov wordlist ordering** (`--order markov`): reorder the wordlist
  candidates so the statistically likeliest words are tried first
  (`candidates.ByScore`), distinct from `--markov` generation.
- **`--time-limit`**: a clearly-named per-file budget to abandon a stuck search
  and move on; a deadline is now a graceful give-up (locked, exit 1), not an
  error.
- **RAR5 fast password verification** (`xcrypto/scheme/rar5`): uses the 8-byte
  check value stored in the RAR5 header to reject a wrong password after key
  derivation alone — no decrypt/decompress — reading the iteration count from
  the header. Cross-validated against the `rar` CLI for `-hp` and `-p` archives.

### Changed
- The GPU PBKDF2-HMAC-SHA1 tier is wired into the **live crack loop**: WinZip-AES
  and encrypted DMG batch their keyspace sweep onto the device (opt-in `xcrackd
  --gpu`), re-checked by the CPU verifier, with transparent CPU fallback.
- Docs: added this changelog and `docs/REFERENCES.md`.

## PR #14 — 2026-10-17 — GPU live loop, on-disk DMG, CLI feature wiring

### Added
- GPU PBKDF2 wired into the live crack loop (`AccelKDF` seam, `Options.Accelerator`).
- On-disk encrypted DMG (`encrcdsa` v2) parsed and cracked directly (AES-128/256),
  validated against real macOS images.
- CLI reach for existing library features: `--combinator-*`, `--increment`,
  `--markov`; `--as sqlcipher` force-format; MS Access detection; encrypted
  Publisher/Visio/Project via the shared OOXML path.

## PR #13 — 2026-10-16 — Candidate sources, adaptive/distributed, streaming, DMG, GPU tier

### Added
- WinZip-AES `$zip2$` hash-line emitter (hashcat `-m 13600`).
- Breach-corpus (`--breach`) and password-spray (`--spray`) candidate sources.
- Adaptive scheduling (`--adaptive`): corpus-wide promotion + smallest-file-first.
- Disk-streaming of large entries (spill above a threshold).
- Keyspace sharding (`--shard I/N`) for manual distribution.
- Encrypted DMG recovery via the `dmg2john` `$dmg$` line (v1/v2), John-vector validated.
- Opt-in OpenCL GPU tier for `xcrackd` (`-tags opencl`), self-tested against the CPU reference.
- PRINCE, toggle-case, keyboard-walk generators.

## PR #11 — 2026-10-16 — CI determinism, hybrid + hash-line attacks, ODF-GCM & KeePass

### Added
- `$office$` / `$pdf$` hash-line emitters (hashcat / John), hashcat-cross-validated.
- Hybrid attack (`--hybrid-append` / `--hybrid-prepend`).
- ODF 1.3 authenticated AES-256-GCM.
- KeePass KDBX4 (`.kdbx`) with an in-tree Argon2d, validated against `argon2` / pykeepass.

### Changed
- Fuzz and qpdf CI gates made deterministic (replay committed corpora / vectors).

### Fixed
- PDF `rebuild` xref-table DoS (bounded object numbers).

## PR #12 — 2026-10-16 — PDF R6 fix

### Fixed
- Off-by-one in the ISO 32000-2 Algorithm 2.B (PDF AES-256 / R6) hash loop, which
  caused intermittent user-password verification failures; validated 300/300
  against qpdf.

## PR #10 — 2026-10-16 — iWork, password-hint candidates, example configs

### Added
- Apple iWork (Pages/Numbers/Keynote) passphrase recovery, reversed and validated
  against real 14.5 samples.
- Password-hint candidate derivation (`--hint`, `--hint-rules`) from embedded hints
  (iWork `.iwph`, ZIP comment).
- Example config files in `config/`.

### Fixed
- Re-detect-after-decrypt picked a non-container format sharing the ZIP magic,
  stopping decomposition; now picks the best container.
- CFB DIFAT sector-chain walk bounded by the file's sector count.

## PR #9 — 2026-10-16 — Sample set

### Added
- `samples/` demo set with a reproducible generator; every passphrase is `opensesame`.

## PR #8 — 2026-10-16 — ZipCrypto known-plaintext + key/data-store formats

### Added
- Full in-tree Biham–Kocher ZipCrypto known-plaintext key recovery (`xcrack kp`),
  with a ~34× two-step fiber speedup and an external `bkcrack` offload, cross-validated.
- OpenSSH keys, encrypted PEM/PKCS#8, JKS, PKCS#12, PuTTY `.ppk`, SQLCipher —
  each cross-validated against the real tool.
- Weir-style PCFG generator (`--pcfg`).

## PR #7 — 2026-10-16 — Search engine depth

### Added
- Full hashcat rule engine; context/association candidates (`--context`);
  per-format fast-reject; checkpoint/resume (`--checkpoint`); Prometheus metrics;
  audit hook; single-password ergonomics, potfile, find-all, progress, logging.

## PR #4 — 2026-10-16 — Service tier + GPU-offload plumbing + new formats

### Added
- `xcrackd` HTTP service and `pkg/api`; challenge export/import; Markov ordering
  primitive; pluggable live candidate provider.
- `age` (scrypt), symmetric OpenPGP (`gpg -c`), header-encrypted 7z/RAR —
  each cross-validated against the real CLI.

## PR #3 — 2026-10-15 — Legacy MS Office

### Added
- `.doc/.xls/.ppt` decryption (RC4 CryptoAPI, Office 97/2000 RC4, XOR), RC4 CryptoAPI
  cross-validated byte-for-byte against gold-standard decrypted documents.
- `Registry.DetectAll` ranked detection with graceful fallback.

## PRs #1–#2 — 2026-10-15 — MVP + Phase 2 foundation

### Added
- Three-module layout (xcrypto / xfileformats / xcrack); recursive decomposition
  engine; ZIP (ZipCrypto + WinZip-AES), OOXML, PDF; pattern engine (masks + rules);
  candidate sources; CLI + renderers; fuzz / bomb / known-answer / race gates;
  `examples/impex-embed`. Phase-2 breadth: ODF, tar/gzip/bzip2/xz/7z/rar,
  `.eml` extraction.
