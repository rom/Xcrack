# Embedding examples

Runnable programs that embed the Xcrack engine (`github.com/rom/xcrack/pkg/xcrack`)
in different ways. Each is a standalone `main` package; build or run one with:

```sh
go run ./xcrack/examples/<name> [args]
```

The full library reference is [`../../docs/API.md`](../../docs/API.md); the
embedding tour is [User Manual §7](../../docs/USERMANUAL.md#7-embedding-the-library).

| Example | What it demonstrates |
|---------|----------------------|
| [`impex-embed`](impex-embed) | The minimal embedding: build one `Pool`, feed files, supply in-memory candidates, log finds via `OnFound`. |
| [`batch-triage`](batch-triage) | A concurrent triage service — many files through one shared `Pool`, a bounded worker fan-out, a JSON line per file, and an aggregate `Metrics` summary. |
| [`candidate-pipeline`](candidate-pipeline) | Composing an advanced candidate stream in Go (wordlist + toggle-case + PRINCE + Markov + dedup + shard) and feeding it via `CandidateProvider`; `-stdout` previews the stream. |
| [`pin-fastreject`](pin-fastreject) | `Options.FastReject` pruning a hopeless keyspace ("the secret is an N-digit PIN") before the KDF, plus implementing a custom `candidates.Source`. |
| [`inspect-tree`](inspect-tree) | Identify-only: run with no candidates and walk the `Result`/`Node` tree, reading each node's bytes through `ContentRef`. |
| [`http-service`](http-service) | Embedding the REST API (`pkg/api.Server`) in your own HTTP server, with an audit hook and optional TLS — the library form of `xcrackd`. |
