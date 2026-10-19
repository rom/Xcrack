# Example configurations

Ready-to-adapt YAML configs for the `xcrack` CLI. Pass one with `--config`:

```sh
xcrack --config config/basic.yaml invoice.zip
```

A config sets the same knobs as the command-line flags; explicit flags and
environment variables override the config (see `docs/USAGE.md` for the full
field reference and precedence rules). Edit the wordlist paths to lists you
actually have.

Some capabilities are command-line modes or per-invocation state rather than
config keys, so they are not shown in these files: the inspection modes
(`--benchmark`/`-b`, `--keyspace`, `--estimate`, `--stdout`, `--debug-rules`,
`--show`/`--left`), the offload bridge (`xcrack export-challenge` /
`--resume-from`), the resume/cache files (`--checkpoint`, `--session`,
`--found-cache`/`--remember`, `--potfile`, `--cluster-session`), and the
candidate transforms (`--min-length`/`--max-length`, `--encoding`, `--loopback`,
`--markov-threshold`, `--markov-pos`, `--increment`, `--combinator-*`,
`--hybrid-*`). Everything else is a config key; the complete reference is at the
end of this file.

| File | For |
|------|-----|
| [`basic.yaml`](basic.yaml) | A wordlist + a few known candidates on top of the built-in list — the simplest useful setup. |
| [`mask-rules.yaml`](mask-rules.yaml) | Mask brute-force + rule mangling + a custom charset. |
| [`hint-and-context.yaml`](hint-and-context.yaml) | Derive candidates from the file's embedded **password hint** (iWork `.iwph`, ZIP comment) and from names/sibling text, then mangle hint words with rules. |
| [`fast-triage.yaml`](fast-triage.yaml) | Quick, CPU-throttled, time-bounded pass to sort many files into "trivially unlocked" vs "needs effort". |
| [`targeted.yaml`](targeted.yaml) | The "smart dictionary" workflow: leak corpus + language list + spray first, Markov-ordered, light human mutations, password reuse across the run. |
| [`deep-batch.yaml`](deep-batch.yaml) | Everything at once on a big box, generous limits, high concurrency — pair with `--checkpoint`. |
| [`distributed.yaml`](distributed.yaml) | Fan the search out across a fleet of `xcrackd` workers (`cluster:` block, collective/partition). |

Try any of them against the bundled [`../samples`](../samples) (passphrase
`opensesame`, or `Password` for the Apple iWork samples):

```sh
xcrack --config config/hint-and-context.yaml samples/apple.pages   # unlocked from the .iwph hint
xcrack --config config/basic.yaml -w samples/wordlist.txt samples/zipcrypto.zip
```

## Complete config-key reference

Every key below is optional; omit a block to take its defaults. CLI flags and
environment variables override the config. This is the one canonical schema: the
`xcrack --config` flag, the embeddable library (`pkg/jobspec`), and the
`xcrack-web` advanced-mode editor all consume it, so a capability expressible
here is reachable from every surface.

### `concurrency:`
| Key | Type | Meaning |
|-----|------|---------|
| `workers` | int | concurrent candidate testers (0 = auto) |
| `file_jobs` | int | files processed in parallel |
| `max_procs` | int | ceiling on OS threads for the search |
| `batch_size` | int | candidates per internal batch (channel amortization) |
| `throttle` | int | CPU duty-cycle percent (1–100; lower = gentler) |
| `dual_pipeline` | bool | race the CPU search and the `--gpu` sweep over one shared keyspace per file (first to find wins; needs `--gpu`) |
| `gpu` | bool | offload the shared PBKDF2 sweep to an OpenCL device (needs a `-tags opencl` build on GPU hardware; pure-Go falls back to the CPU) |

### `limits:`
| Key | Type | Meaning |
|-----|------|---------|
| `max_depth` | int | max container nesting depth (0 = default 32) |
| `max_total_bytes` | int64 | cumulative decompressed-byte budget |
| `max_nodes` | int | max extracted entries |
| `max_entry_size` | int64 | max single-entry size |
| `max_ratio` | int | max decompression ratio (zip-bomb guard) |
| `max_candidates` | int64 | max candidates tested per encrypted node (0 = unlimited) |

### `recursion:`
| Key | Type | Meaning |
|-----|------|---------|
| `recurse` | bool | decompose containers (default true) |
| `explode_documents` | bool | decompose documents into internal parts |

### `search:`
| Key | Type | Meaning |
|-----|------|---------|
| `promote_passwords` | bool | try ancestor-recovered passwords first (default true) |
| `context_candidates` | bool | guesses from names + plaintext siblings (`--context`) |
| `hint_candidates` | bool | guesses from an embedded password hint (`--hint`) |
| `hint_rules` | []string | hashcat rules applied to hint words |
| `hybrid_append` / `hybrid_prepend` | []string | masks combined with each wordlist word |
| `toggle_case` / `prince` / `keyboard_walk` | bool | extra generators |
| `spray` | bool | curated spray set (`--spray`) |
| `spray_tokens` | []string | org/product/user tokens mangled into the spray set |
| `adaptive` | bool | corpus-wide password reuse across files (`--adaptive`) |
| `cost_queue` | bool | attack weakest/fastest files first (`--cost-queue`) |
| `markov` | bool | Markov best-first generation (`--markov`) |
| `markov_pos` | bool | position-aware (2D) Markov model (`--markov-pos`) |
| `markov_max` | int | cap on Markov guesses (0 = 1,000,000) |
| `markov_threshold` | int | per-position branching cap (0 = 15; `--markov-threshold`) |
| `order` | string | `markov` to reorder wordlists likeliest-first (`--order`) |
| `order_max` | int | max wordlist entries buffered for reordering (0 = 1,000,000) |
| `pcfg` | bool | PCFG probability-order generation (`--pcfg`) |
| `pcfg_max` | int | cap on PCFG guesses (0 = 100,000) |
| `increment` | string | expand each mask over `MIN:MAX` tokens, shortest first (`--increment`) |
| `combinator` | `{left, right, sep}` | combinator attack: every left word + every right word, joined by `sep` |
| `loopback` | bool | re-mangle cached/pot passwords through the rules (`--loopback`) |
| `find_all` | bool | **reserved — not yet active.** Intended to keep searching every encrypted node even if some stay locked; accepted today but ignored by the engine (which already explores every node by default) |
| `spray_years` | []int | years used in spray patterns (default current/previous) |
| `shard` | string | `I/N` keyspace stride for this worker (`--shard`) |

### `candidates:`
| Key | Type | Meaning |
|-----|------|---------|
| `wordlists` | []string | wordlist files (gzip ok; `-` = stdin) |
| `passwords` | []string | explicit candidate passwords (tried first) |
| `breach` | []string | frequency-annotated leak corpora (tried ahead of wordlists) |
| `breach_min_count` | int64 | drop breach entries seen fewer than N times |
| `use_default_list` | bool | include the built-in common-password list (default true) |
| `swedish` | bool | also try the built-in Swedish-targeted list |
| `password_files` | []string | files of candidate passwords (one per line), tried first |
| `min_length` / `max_length` | int | skip candidates outside this character length (0 = no bound) |
| `encoding` | string | transcode candidates before testing: `utf-8` (default) \| `latin1` \| `utf-16le` \| `utf-16be` |

### `patterns:`
| Key | Type | Meaning |
|-----|------|---------|
| `masks` | []string | hashcat masks (`?l?u?d?s?a?b`, `?1..?4`) |
| `rules` | []string | hashcat mangling-rule lines |
| `custom_charsets` | map | `"1".."4"` → charset string for `?1..?4` |
| `hcmask` | []string | hashcat `.hcmask` files (per-line masks; `--hcmask`) |
| `generate_rules` | int | generate N reproducible random mangling rules (`--generate-rules`) |
| `generate_rules_seed` | int64 | seed for `generate_rules` (same seed → same rules) |

### `input:`
| Key | Type | Meaning |
|-----|------|---------|
| `as` | string | force a scheme for a magic-less file, e.g. `sqlcipher` (`--as`) |

### `output:`
| Key | Type | Meaning |
|-----|------|---------|
| `format` | string | `text` \| `json` \| `jsonl` |
| `results_file` | string | append a JSON result manifest here |
| `log_level` | string | `debug` \| `info` \| `warn` \| `error` |
| `log_format` | string | log + audit trail format: `text` (default) \| `json` |
| `log_file` | string | append the structured log + audit trail to this file (default: stderr) |
| `syslog` | bool | send the log + audit trail to the system logger instead of stderr/file |
| `syslog_address` | string | remote syslog `host:port` (with `syslog`; empty = local socket) |
| `syslog_network` | string | remote syslog transport `udp` \| `tcp` (with `syslog_address`) |
| `syslog_tag` | string | syslog tag/ident (with `syslog`; default: program name) |
| `audit_log_password` | bool | include the recovered password in the "file cracked" audit entry (default off: the trail stays secrets-free) |
| `extract_suffix` | string | per-source extracted-tree directory suffix under `--out` (default `.extracted`; single path segment, no `/` or `..`) |
| `cache_encryption` | string | encrypt the found-password cache at rest: `` / `none` (plaintext, default) or `tpm` (seal the key to the host TPM; needs a `-tags tpm` build) |

### `budget:`
| Key | Type | Meaning |
|-----|------|---------|
| `per_file` | duration | give up on a file after this (e.g. `30m`); reported locked, not errored |
| `total` | duration | whole-run deadline |

### `cluster:` (distributed runs — see [`distributed.yaml`](distributed.yaml))
| Key | Type | Meaning |
|-----|------|---------|
| `servers` | list of `{url, group}` | xcrackd endpoints to distribute across |
| `mode` | string | `collective` (share one file) \| `partition` (groups take different files) |
| `batch` | int | candidates shipped per server request |
| `allow_defaults` | bool | let each server also try its own default list |
| `per_request` | duration | per-request server deadline hint (e.g. `30s`) |
| `tls.ca` | string | PEM CA bundle to verify `https://` server certs (private CA / self-signed) |
| `tls.cert` | string | client certificate (PEM) for mutual TLS to the servers |
| `tls.key` | string | private key (PEM) for `tls.cert` |
| `tls.server_name` | string | expected server cert name (SNI / verification override) |
| `tls.insecure` | bool | skip server certificate verification (**insecure** — testing only) |

> Server-side TLS is an `xcrackd` runtime flag, not a config key: run
> `xcrackd --tls-cert server.crt --tls-key server.key` (add `--tls-client-ca
> ca.crt` for mutual TLS). Generate certs with
> [`scripts/gen-selfsigned-cert.sh`](../scripts/gen-selfsigned-cert.sh) or
> [`scripts/gen-letsencrypt-cert.sh`](../scripts/gen-letsencrypt-cert.sh).
