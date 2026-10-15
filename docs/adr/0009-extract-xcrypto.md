# ADR-0009 — Extract all crypto + cracking into the standalone Xcrypto module

Status: Accepted · Serves: QA-2, QA-4, QA-10, CON-1, CON-4 · Supersedes part of
[ADR-0002](0002-standalone-xfileformats-library.md)

## Context
[ADR-0002](0002-standalone-xfileformats-library.md) split file-format knowledge
into Xfileformats, but the *cryptography* (KDFs, ciphers, per-scheme
verify/decrypt) and the *cracking* logic (candidate generation, the pattern
engine, the concurrent search) were spread between Xfileformats (schemes) and
Xcrack (candidates, search). Other internal tools want to attack an encrypted
blob — verify a password, decrypt with a key, run a wordlist/mask against a
challenge — without pulling in file-format parsing or the recursion engine.

## Decision
Introduce a third module, `github.com/rom/xcrypto`, holding **all** crypto and
cracking code, with no file-format or recursion knowledge and no third-party
dependencies:

- `prim` — primitives (PBKDF2, AES CTR/CBC/ECB, RC4, Office agile/standard
  key derivation, UTF-16LE, constant-time compare);
- `scheme/*` — the concrete encryption schemes (ZipCrypto, WinZip AES, OOXML
  agile + standard, PDF later), each parameterised by a `Challenge`;
- `candidates` — candidate sources (moved out of Xcrack);
- `pattern` — the hashcat-compatible mask + rule engine;
- `attack` — the crypto/cracking engine: a concurrent password search over a
  `Probe` (a single-password test) and a candidate `Source`, bounded by one
  reusable global semaphore.

`Challenge` (the KDF/cipher/verifier vocabulary) moves to Xcrypto and becomes the
contract between layers. Xfileformats parses structure and **builds** a
Challenge; Xcrypto **consumes** it. Xcrack orchestrates recursion and uses
`attack` for the per-challenge search.

## Options considered
1. **Leave crypto in Xfileformats, cracking in Xcrack.** Simplest, but no reuse
   boundary: a tool wanting only "crack this challenge" would drag in format
   parsing and/or the recursion engine. Rejected — reuse was explicitly asked
   for.
2. **One module for crypto, a separate module for the cracking engine.**
   Possible, but the pattern engine, candidate sources, and search are naturally
   cohesive with the schemes (they all operate on passwords/challenges) and
   share the dependency-free, format-agnostic character. Kept them together as
   sub-packages of one module, which is still "a separate crypto library and
   engine" and avoids a fourth go.mod.
3. **Extract everything into Xcrypto (chosen).**

## Consequences
- **+** Any tool can `import github.com/rom/xcrypto` to derive keys, verify,
  decrypt, or run a wordlist/mask against a challenge — no formats, no recursion
  (QA-4). The schemes and primitives are unit-tested in isolation.
- **+** Reinforces QA-2/CON-1: the crypto is pure-Go, dependency-free, and never
  touches document semantics; the one third-party dependency (`yaml.v3`) stays
  in the CLI only.
- **+** Clear single home for "best-effort attack the encrypted file": the
  `attack` engine plus the candidate/pattern packages.
- **−** A third `go.mod` and two more `replace` directives (handled by the
  `go.work` workspace); `Challenge` moving modules was a one-time churn across
  Xfileformats and Xcrack.
- Xfileformats now depends on Xcrypto; Xcrack depends on both. The dependency
  graph stays a DAG (xcrack → xfileformats → xcrypto, and xcrack → xcrypto).
