# Example configurations

Ready-to-adapt YAML configs for the `xcrack` CLI. Pass one with `--config`:

```sh
xcrack --config config/basic.yaml invoice.zip
```

A config sets the same knobs as the command-line flags; explicit flags and
environment variables override the config (see `docs/USAGE.md` for the full
field reference and precedence rules). Edit the wordlist paths to lists you
actually have.

| File | For |
|------|-----|
| [`basic.yaml`](basic.yaml) | A wordlist + a few known candidates on top of the built-in list — the simplest useful setup. |
| [`mask-rules.yaml`](mask-rules.yaml) | Mask brute-force + rule mangling + a custom charset. |
| [`hint-and-context.yaml`](hint-and-context.yaml) | Derive candidates from the file's embedded **password hint** (iWork `.iwph`, ZIP comment) and from names/sibling text, then mangle hint words with rules. |
| [`fast-triage.yaml`](fast-triage.yaml) | Quick, CPU-throttled, time-bounded pass to sort many files into "trivially unlocked" vs "needs effort". |
| [`deep-batch.yaml`](deep-batch.yaml) | Everything at once on a big box, generous limits, high concurrency — pair with `--checkpoint`. |

Try any of them against the bundled [`../samples`](../samples) (passphrase
`opensesame`, or `Password` for the Apple iWork samples):

```sh
xcrack --config config/hint-and-context.yaml samples/apple.pages   # unlocked from the .iwph hint
xcrack --config config/basic.yaml -w samples/wordlist.txt samples/zipcrypto.zip
```
