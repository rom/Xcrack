# Performance

How fast Xcrack is, and why. The short version: **cracking speed is set almost
entirely by the target format's per-candidate key-derivation cost**, not by
Xcrack's machinery. A cheap verifier runs hundreds of thousands of guesses per
second; a deliberately expensive KDF runs single digits. Xcrack's job is to pay
that cost as few times as possible — order the likely guesses first, take
shortcuts and key-level attacks where the crypto allows, and spread the work
across cores, machines or a GPU.

> **About the numbers.** The rates below were measured on one specific machine
> (noted inline) and are *indicative*, not guarantees. They scale with core
> count and with the file's own iteration parameters (most KDF costs are parsed
> per-file). Always measure your own target with `xcrack --benchmark` /
> `--estimate` — those read the real parameters out of *your* file.

## Measure your own target

Three inspection flags report performance without cracking anything:

- `xcrack --benchmark FILE` — probes the real verifier and hammers it with wrong
  candidates for ~2 s, printing `FILE [scheme] <rate> candidates/sec`.
- `xcrack --keyspace …` — the exact (or `>=`, capped by `--limit`) candidate
  count for the configured attack.
- `xcrack --estimate FILE` — measures the rate (~1.5 s), computes the keyspace,
  and prints worst-case and expected time:

```
$ xcrack --estimate -w list.txt secret.7z
    rate      27 candidates/sec
    keyspace  41
    time      ~1.52s to exhaust, ~760ms expected to a hit
```

Expected time is `keyspace / (2 × rate)`; worst case is `keyspace / rate`.
`--cost-queue` uses the same measurement to attack the weakest/fastest files in
a batch first.

## Measured verify rates (single box, CPU, pure-Go)

Measured with `xcrack --benchmark` on the project's `samples/` fixtures, on a
**4-core Intel Xeon @ 2.10 GHz**, default pure-Go build (no GPU). One candidate =
one full KDF + verifier run. Your absolute numbers will differ; the **relative**
ordering (which formats are cheap vs. expensive) is what transfers.

| Format (sample) | candidates/sec | Dominant per-candidate work |
| --- | ---: | --- |
| JKS keystore | ~510,000 | one SHA-1 over password + file body |
| traditional PEM (`EVP_BytesToKey`) | ~93,000 | one MD5 |
| ZipCrypto (password mode) | ~62,000 | PKWARE stream init + check byte |
| PKCS#12 (`.p12`) | ~3,700 | RFC 7292 KDF, low iterations |
| PKCS#8 PBES2 PEM | ~2,000 | PBKDF2, low iterations |
| WinZip-AES-256 | ~1,050 | PBKDF2-HMAC-SHA1 ×1000 |
| PDF (AESV3 / R6) | ~370 | iterated SHA-2 (Algorithm 2.B, ≥64 rounds) |
| iWork (Pages/Numbers/Keynote) | ~42 | PBKDF2-HMAC-SHA1 ×(tens of thousands) |
| RAR5 | ~40 | PBKDF2-HMAC-SHA256 ×2^Lg2Count |
| 7-Zip (AES-256) | ~30 | SHA-256 iterated |
| PuTTY `.ppk` v3 | ~9 | Argon2 (memory-hard) |
| OpenPGP (`gpg -c`) | ~6 | iterated S2K |
| OpenSSH private key | ~4 | bcrypt-pbkdf |
| age (passphrase) | ~1 | scrypt (very memory-hard) |

The ~500,000× spread between JKS and age is entirely the KDF: both do a tiny
amount of "real" verification, but age's scrypt is designed to cost a large
amount of memory and time *per guess*.

## Why the rates differ — the cost model

The per-candidate cost comes straight from each scheme's parameters (file
references are to `xcrypto/scheme/<name>/` unless noted):

| Tier | Schemes | Cost driver |
| --- | --- | --- |
| **Trivial** (one hash) | JKS (`jks.go`), traditional PEM MD5 `EVP_BytesToKey` (`privkey`), VBA project (`SHA1(pw‖salt)`, `vbaproject.go`) | a single SHA-1/MD5 per guess |
| **Broken cipher** | ZipCrypto (`zipcrypto`) | no KDF at all — see [key-level attacks](#key-level-attacks-no-password) |
| **Light PBKDF2** | WinZip-AES (`PBKDF2Iter = 1000`, `winzipaes.go`), DMG (default 1000, `dmg.go`), PBES2 PEM, PKCS#12 (default 1 iter) | PBKDF2 with a low iteration count |
| **Heavy PBKDF2 / iterated hash** | iWork (parsed, ~100000), SQLCipher v3 (PBKDF2-SHA1 ×64000) / v4 (PBKDF2-SHA512 ×256000, `sqlcipher.go`), MS Office agile (spinCount, real files ~100000, `ooxml.go`), legacy Office standard (SHA-1 ×50000), RAR5 (2^Lg2Count), 7-Zip (SHA-256 iterated) | tens of thousands to millions of hash iterations |
| **PDF (variant-dependent)** | R2 (1 MD5 + 1 RC4), R3/R4 (50 MD5 + 20 RC4), R5 (single SHA-256), R6 (Algorithm 2.B ≥64 SHA-2) (`pdf/pdf.go`) | varies by revision — R5 is near raw-hash speed, R6 is iterated |
| **Memory-hard** | age scrypt (`age.go`), Ethereum scrypt (`ethkeystore.go`), KeePass KDBX4 Argon2 (`keepass.go`), PuTTY v3 Argon2 (`puttykey.go`), OpenSSH bcrypt-pbkdf (`sshkey.go`) | large memory region per guess; deliberately GPU-hostile |

Most iteration counts are **parsed from the file**, not fixed — a document author
can crank them up, so your file may be slower than the sample. `--benchmark`
reports the real rate for your file.

## Attack methods and their effort

Total time = **keyspace × per-candidate cost**. Both factors matter: a fast
format with a huge keyspace is still hopeless, and a slow format with a tiny
keyspace is quick.

| Method | Flag(s) | Keyspace shape |
| --- | --- | --- |
| Single / explicit | `-p STR` | 1–few |
| Dictionary | `-w FILE` | the list (tens → millions) |
| Dictionary + rules | `-w` + `--pattern` | list × rules |
| Mask / brute force | `--hcmask`, `?l?u?d?s?a`, `--increment` | product of charset sizes |
| Hybrid | `--hybrid-append/-prepend` | list × mask tail |
| Combinator | `--combinator-*` | left × right |
| Generators | `--markov`, PRINCE, PCFG, keyboard-walk, toggle-case | best-first, bounded |
| Key-level (no password) | `kp`, `office-keyattack`, `pdf-keyattack` | fixed key space, password-independent |

A mask grows explosively: `?a` (95 printable) to length 8 is 95⁸ ≈ 6.6 × 10¹⁵
candidates — millennia even at ZipCrypto's ~62k/s. Prefer dictionary + rules,
best-first generators, and length-incrementing masks (`--increment`); use
`--estimate` before committing to a mask. Markov/PCFG ordering and the
breach/spray/language sources exist to put the few likely guesses first so the
expensive KDF is paid as rarely as possible.

## Key-level attacks (no password)

A few legacy schemes let you recover the **key** directly, independent of
password strength — the one case where a "long random password" does not save
the file.

- **ZipCrypto** (Biham–Kocher known-plaintext). With aligned known plaintext the
  three 32-bit internal keys are recovered with no password. Measured in the
  repo: the two-step fiber search runs **~16 / 28 / 62 candidates·s⁻¹ on 1 / 2 /
  4 cores**; a representative full recovery (54-byte known plaintext) examined
  **~185k candidates and recovered the keys in ~57 min on a 4-core box**
  (see [`USAGE.md`](USAGE.md)). One recovery unlocks a whole archive
  (`kp --zip`), and a local `bkcrack` offload is a further constant factor.
- **Office 97/2000 RC4** and **PDF V1/R2 (+ 40-bit R3/R4) RC4** derive a 40-bit
  key, so the 2⁴⁰ ≈ 1.1 × 10¹² key space is sweepable. On the 4-core box above,
  the pure-Go CPU sweep runs **~0.45M keys/s per core** (derived from
  `BenchmarkRC4KeyAttack`, which scans a 16384-key window in ~36 ms), i.e.
  **~1.8M keys/s on 4 cores** — a full worst-case 2⁴⁰ sweep in roughly **a week**
  of CPU, ~half that expected-to-hit. This is the case the **GPU key-search
  kernels** (`office-keyattack --gpu`, `pdf-keyattack --gpu`) and precomputed
  "Thunder Tables" exist for: the work is embarrassingly parallel, so a real GPU
  cuts it by a large constant factor. Shard it with `--shard I/N` across hosts.

## Platforms and scaling

- **Single CPU.** The password search is independent per candidate, so it scales
  **near-linearly** with cores (the ZipCrypto 16/28/62 figures on 1/2/4 cores are
  a measured example). `--file-jobs` additionally cracks multiple files
  concurrently.
- **Distributed.** `--shard I/N` runs disjoint strides on separate machines; a
  fleet of `xcrackd` servers (`--server URL[@GROUP]`, `--cluster-mode`) splits one
  keyspace, resumable with `--cluster-session`. Linear in machines for the big
  keyspaces.
- **GPU / OpenCL** (server tier, `xcrackd --gpu`, `-tags opencl`). The device runs
  the heavy, parallel step — the KDF or the key sweep — in bulk batches; the CPU
  keeps parsing, recursion and the authoritative re-check. Accelerated:
  PBKDF2-HMAC-SHA1/256/512 (WinZip-AES, DMG, ODF, RAR5, SQLCipher-v4-class), the
  Office agile/standard spin, the Office 97/2000 and PDF 40-bit **key searches**,
  and the VBA salted-SHA-1 batch. It auto-tunes the batch size per device and
  splits batches across multiple devices. **Not** accelerated (stay on CPU):
  Argon2, scrypt and bcrypt (memory-hard / Blowfish, GPU-hostile), and SQLCipher
  (ambiguous v3/v4 profile). The in-repo validation device is **pocl** (CPU
  OpenCL), which proves kernel correctness but gives no speed-up; real throughput
  comes from actual GPU hardware. See [`CRACKING.md`](CRACKING.md) §4.
- **External offload.** `xcrack hashline` emits hashcat/John lines
  (`$office$`/`$pdf$`/`$zip2$`/`$dmg$`), and `xcrack export-challenge` +
  `--resume-from` round-trips a portable challenge — hand the heavy search to a
  GPU rig or a dedicated tool and re-import the recovered password.

## Practical guidance

- **Triage a batch** with `--cost-queue` (weakest/fastest schemes first) and
  `--time-limit D` so one hard file never blocks the rest; `--adaptive` reuses a
  found password across the run.
- **Avoid paying twice.** `--found-cache` / `--remember` tries known passwords
  first (skips wrong-guess KDFs), and `--reuse-output -o DIR` skips an unchanged
  source entirely on re-extraction (a warm run drops from seconds to
  milliseconds — see [`FAQ.md`](FAQ.md#candidate-generation-and-ordering)).
- **Match the method to the cost.** On an expensive KDF (age, Argon2, 7-Zip) a
  big mask is futile — lean on targeted lists, hints/context, Markov/PCFG
  ordering, and the key-level shortcuts. On a cheap-but-broken scheme (ZipCrypto,
  40-bit Office/PDF) go straight to the key attack.

See [`TESTS.md`](TESTS.md) for how the benchmarks and cross-validation are run,
and [`CRACKING.md`](CRACKING.md) for the attack chosen per format.
