# Xcrack FAQ

Answers grouped by topic. See also [`USAGE.md`](USAGE.md) (worked examples),
[`CRACKING.md`](CRACKING.md) (how each format is attacked),
[`FILEFORMATS.md`](FILEFORMATS.md) (the format catalogue),
[`config/README.md`](../config/README.md) (config keys), and
[`REFERENCES.md`](REFERENCES.md).

> Xcrack is a recovery / defensive tool. Use it only on files you own or are
> explicitly authorized to access.

---

## File formats

**Which formats can Xcrack open?**
Archives (ZipCrypto, WinZip-AES, 7-Zip, RAR4/RAR5), Microsoft Office (legacy
97/2000/XP-2003 and OOXML 2007/2010+, incl. Publisher/Visio/Project via the
shared Office path), PDF, OpenDocument (ODF), Apple iWork, encrypted DMG, keys
and stores (OpenSSH, PEM/PKCS#8, JKS, PKCS#12, PuTTY .ppk, SQLCipher, KeePass
KDBX3/KDBX4), Ethereum keystore wallets, age (passphrase), and symmetric
OpenPGP (`gpg -c`). The full catalogue with cross-validation notes is in
[`FILEFORMATS.md`](FILEFORMATS.md).

**How does it know the format?** By content, not extension: each format reports a
confidence from a bounded peek of the file head. Container formats (ZIP, Office
CFB) are decomposed recursively, so an encrypted document inside an encrypted
archive is found automatically.

**A format has no magic bytes (SQLCipher).** Force it with `--as sqlcipher`
(magic-less formats are not auto-detected so they cannot mis-claim other files).

**Does it decrypt the file or just find the password?** For whole-file formats it
decrypts and writes the tree out (`--out DIR`). For key/credential stores and
wallets it is **verify-only**: the recovered passphrase is the deliverable; the
private key / database body is not reconstructed.

---

## Attack orchestration

**How are many files processed?** Concurrently (`--file-jobs`), each with its own
candidate stream. Output stays in argument order regardless of dispatch order.

**Which file is attacked first?** Argument order by default. `--cost-queue`
benchmarks each file and attacks the fastest/weakest schemes first; `--adaptive`
dispatches smallest-first and reuses any found password across the whole run.

**Can I split the work across machines?** Two ways: `--shard I/N` (run disjoint
strides on separate hosts), or a fleet of `xcrackd` servers via
`--server URL[@GROUP]` + `--cluster-mode collective|partition`. An interrupted
fleet run resumes with `--cluster-session FILE` (skips candidates already tried).

**Can I offload to hashcat/John or a GPU box?** Yes — `xcrack hashline` emits
`$office$`/`$pdf$`/`$zip2$`/`$dmg$` lines, and `xcrack export-challenge` emits a
portable JSON challenge; re-import the recovered password with `--resume-from`.
The server tier also has an in-process OpenCL GPU option (`xcrackd --gpu`).

**Can I stop a run and resume it?** Yes. `--checkpoint FILE` resumes one long
single-file run where it stopped; `--session FILE` resumes a whole multi-file
batch (finished files are skipped on re-run).

---

## Cracking alternatives (do I even need to brute force?)

**Does it try shortcuts before brute force?** Always. It tries the found-password
cache, embedded hints, the empty password and `VelvetSweatshop`, and — where the
crypto allows — a direct key attack instead of a password search. See
[`CRACKING.md`](CRACKING.md) §3.

**What are the non-brute-force recoveries?** ZipCrypto known-plaintext key
recovery (`xcrack kp`, no password needed); the Office 97/2000 40-bit key attack
(`office-keyattack`); owner/permission-only PDFs and read-only Office docs that
open with the empty password / VelvetSweatshop.

**My password is long and random — is it hopeless?** Not necessarily. ZipCrypto
and Office 97/2000 are attackable at the **key** level regardless of password
strength, and a reused password may be in your found-password cache or caught by
`--loopback`.

---

## Cracking methods

**What attack modes exist?** Dictionary (`-w`) with rule mangling (`--pattern`),
mask brute force (`?l?u?d?s?a?b`, `?1..?4`, `--increment`, `.hcmask`), hybrid
(`--hybrid-append/-prepend`), combinator (`--combinator-*`), PRINCE, toggle-case,
keyboard-walk, Markov and PCFG generation, plus the key-level attacks above. The
full matrix is in [`roadmap-enhancements.md`](roadmap-enhancements.md) §4.

**What is loopback?** `--loopback` feeds recovered passwords back through the
mangling rules — it catches a reused password that gained a new suffix or case
("Summer2023" → "Summer2024!").

**Can I preview or debug an attack without cracking?** Yes: `--stdout` prints the
candidate stream, `--keyspace` its size, `--benchmark` the per-file verify rate,
`--estimate` the time-to-crack, and `--debug-rules` the per-rule hit/reject stats.

---

## KDFs (key-derivation functions)

**Which KDFs are implemented?** PBKDF2 (HMAC-SHA1/256/512), scrypt, Argon2
(d/i/id, in-tree), bcrypt-pbkdf, the Office iterated-hash KDFs (agile/standard),
the Office 97/2000 MD5 schedule, the KeePass AES-KDF, OpenPGP S2K, PKCS#12's
RFC 7292 KDF, and EVP_BytesToKey.

**Why are some files so slow to crack?** The KDF is deliberately expensive
(Argon2 with tens of MiB of memory, scrypt N=262144, PBKDF2 ×256000, Office spin
×100000). That cost is per candidate and inherent — use `--benchmark`/`--estimate`
to see the rate, and the found-password cache / hints / key attacks to avoid the
search entirely.

**Which KDFs get GPU acceleration?** PBKDF2-HMAC-SHA1/256/512 today. Memory-hard
KDFs (Argon2, scrypt) and bcrypt stay on the CPU by design. See
[`CRACKING.md`](CRACKING.md) §4.

---

## Ciphers and modes

**Which ciphers/modes are handled?** AES in CTR, CBC, ECB and GCM; RC4 (the
PKWARE/Office schedules); 3DES key-unwrap (DMG); ChaCha20-Poly1305 (age); Blowfish
(bcrypt); and the PKWARE ZipCrypto stream cipher.

**Does it verify authenticity?** Where the format authenticates (GCM tag, HMAC,
OpenPGP MDC, keystore MAC) the tag/MAC is the verifier, so a wrong key is rejected
with cryptographic certainty — no false positives. Unauthenticated modes use the
format's own verifier block (an encrypted known value and its hash).

---

## Verification shortcuts

**What is a "verifier"?** A small value that tells a right guess from a wrong one
without decrypting the whole file — a MAC, an encrypted check block, a check
byte. Xcrack uses the cheapest authoritative verifier each format offers, so a
wrong candidate costs one KDF run, not a full decrypt.

**What is a "fast-reject"?** An even cheaper 1–2 byte pre-check (ZipCrypto's check
byte ≈ 1/256, WinZip-AES's 2-byte value, OpenPGP's CFB quick-check, RAR5's 8-byte
header check) tried *before* the KDF to discard most wrong guesses instantly. A
flagged candidate is always re-checked by the authoritative verifier.

**Can a fast path cause a false positive?** No. Every shortcut and every GPU
result is re-validated by the authoritative verifier (and ZipCrypto key recovery
by a full CRC re-check).

---

## Candidate generation and ordering

**In what order are candidates tried?** Highest-yield first: cached/recovered
passwords → default list (empty + VelvetSweatshop first) → hints/context → spray
→ breach → language lists → wordlists (± rules) → masks/hybrid/generators. See
[`CRACKING.md`](CRACKING.md) §1.

**What is the found-password cache?** `--found-cache FILE` (or `--remember` for a
default location) persists every recovered password and tries the whole cache
**first** on the next run — so a reused password is recovered instantly. It is a
potfile; point it at a shared file across runs and reuse is automatic.

**How do I make the likely guesses come first?** `--order markov` reorders a
wordlist likeliest-first; `--markov` / `--markov-pos` *generate* best-first
guesses (position-aware), with `--markov-threshold` capping the branching; the
breach and spray sources are frequency-ordered.

**Can I restrict candidate length or encoding?** Yes: `--min-length`/`--max-length`
(characters) and `--encoding utf-8|latin1|utf-16le|utf-16be` (for passwords from a
legacy code page or needed as raw UTF-16).

---

## Cryptanalysis

**Does Xcrack do real cryptanalysis, or just guess passwords?** Both. ZipCrypto's
PKWARE cipher is cryptographically broken, so Xcrack recovers its key from known
plaintext (Biham–Kocher) with no password. Office 97/2000 has a 40-bit key
bottleneck, so Xcrack attacks the key directly. These are implemented from the
algorithms with the project's own verified primitives — no third-party crypto.

**Why not attack the key for everything?** Because most modern schemes have no
such weakness: their key derives from a 128/256-bit (or memory-hard) secret with
no shortcut, so the password search is the only route. [`CRACKING.md`](CRACKING.md)
§3 lists what is and isn't attackable, including staged weaknesses (MS Access Jet
header XOR, PDF 40-bit RC4) and ones judged not worth it.

**Is every crypto result trustworthy?** Each scheme is cross-validated against an
external oracle (published test vectors or a real CLI like openssl/keepassxc/
pycryptodome) before shipping; hostile-input parsers are fuzzed.

---

## Configuration settings

**Flags vs config file?** Anything a flag sets, a `--config FILE` YAML can set
too; explicit flags and environment variables override the config. The complete
key reference is in [`config/README.md`](../config/README.md), with ready-to-adapt
examples (`basic`, `mask-rules`, `hint-and-context`, `fast-triage`, `targeted`,
`deep-batch`, `distributed`).

**What's *not* a config key?** Per-invocation modes and state: the inspection
modes, the resume/cache files (`--checkpoint`, `--session`, `--found-cache`,
`--potfile`, `--cluster-session`), and the candidate transforms. Use flags for
those.

**How do I keep a secret off the command line?** `--password-env VAR` or
`--password-file FILE` (argv is visible to `ps`).

---

## Command-line options

**Where's the full list?** `xcrack --help`. Subcommands: `xcrack` (crack),
`identify`, `kp` (ZipCrypto known-plaintext), `hashline`, `export-challenge`,
`office-keyattack`, `version`.

**The most useful flags.**

| Need | Flag |
|------|------|
| wordlist / explicit password | `-w FILE` / `-p STR` |
| rules + masks | `--pattern FILE`, `--increment MIN:MAX`, `--hcmask FILE` |
| remember & reuse found passwords | `--found-cache FILE` / `--remember`, `--loopback` |
| resume | `--checkpoint FILE` (one file), `--session FILE` (batch) |
| triage many files | `--cost-queue`, `--fast-triage` config, `--time-limit D` |
| inspect without cracking | `--stdout`, `--keyspace`, `--benchmark`, `--estimate`, `--debug-rules`, `--show`/`--left` |
| restrict candidates | `--min-length`/`--max-length`, `--encoding` |
| distribute | `--shard I/N`, `--server URL`, `--cluster-session FILE` |
| key-level attacks | `xcrack kp …`, `xcrack office-keyattack FILE` |

Full worked examples are in [`USAGE.md`](USAGE.md).
