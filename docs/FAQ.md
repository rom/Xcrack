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
OpenPGP (`gpg -c`). It also unpacks the plain (non-encrypted) compressors and
containers — tar, gzip, bzip2, xz/lzma, **zstd**, **lz4**, and `.eml`/MIME — so a
protected file wrapped in one (e.g. `.tar.zst` or `.tar.lz4`) is reached and
cracked. The full catalogue with cross-validation notes is in
[`FILEFORMATS.md`](FILEFORMATS.md); the vocabulary is in
[`TERMINOLOGY.md`](TERMINOLOGY.md).

**How does it know the format?** By content, not extension: each format reports a
confidence from a bounded peek of the file head. Container formats (ZIP, Office
CFB) are decomposed recursively, so an encrypted document inside an encrypted
archive is found automatically.

**A format has no magic bytes (SQLCipher, VBA project).** Force it with
`--as sqlcipher` / `--as vbaproject` (magic-less or carrier-embedded formats are
not auto-detected so they cannot mis-claim other files).

**Can it crack a VBA macro / "lock project for viewing" password?** Yes.
`xcrack vba-recover FILE` reads the VBA project password out of a legacy
`.doc/.xls/.ppt`, a macro-enabled OOXML (`.docm/.xlsm/.pptm`), or a standalone
`vbaProject.bin`. If the password is stored in the clear (older projects) it is
printed with no cracking; otherwise it is a salted SHA-1 (`SHA1(pw‖salt)`), which
`vba-recover` emits as John `dynamic_24` / hashcat `-m 110 --hex-salt` lines, and
`xcrack --as vbaproject -w LIST FILE` cracks in-engine. The VBA source itself is
never encrypted — the password only gates the IDE — so the password is the
deliverable.

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
recovery (`xcrack kp`, no password needed) and cross-entry reuse that unlocks a
whole archive from one recovery (`kp --zip`); the Office 97/2000 40-bit key
attack (`office-keyattack`) and the PDF 40-bit RC4 file-key attack
(`pdf-keyattack`); the MS Access Jet header-XOR decode (`access-recover`, no
cracking); owner/permission-only PDFs and read-only Office docs that open with
the empty password / VelvetSweatshop.

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

**Which KDFs get GPU acceleration?** PBKDF2-HMAC-SHA1/256/512 and the Office
agile/standard iterated-hash spin (SHA-1/256/384/512). Memory-hard KDFs (Argon2,
scrypt) and bcrypt stay on the CPU by design. See the **GPU acceleration**
section below and [`CRACKING.md`](CRACKING.md) §4.

---

## GPU acceleration

**Is it on by default?** No. The default build is pure-Go and CPU-only; the GPU
tier is a server-only, opt-in exception. Build `xcrackd` with `-tags opencl`
(needs an OpenCL SDK + runtime and cgo) and run it with `--gpu`. The `xcrack`
CLI and the default `xcrackd` never touch a GPU, and CI never builds the path.

**What does the GPU actually do?** Only the one heavy, embarrassingly-parallel
step — the key derivation — in bulk batches. Format parsing, recursion, and the
authoritative verification all stay on the CPU in pure Go. The device never
decides correctness: every GPU-derived key is re-checked by the format's normal
verifier, so a faulty or mismatched backend can only slow a search, never cause
a false positive or a wrong "found".

**Which formats are accelerated today?**

| Kernel | Formats |
|--------|---------|
| PBKDF2-HMAC-SHA1 | WinZip-AES, encrypted DMG, **ODF** |
| PBKDF2-HMAC-SHA256 | **RAR5** (the 8-byte password-check derivation) |
| PBKDF2-HMAC-SHA512 | PBKDF2-SHA512 schemes |
| **Office iterated-hash spin** (SHA-1/256/384/512) | **Office 2010+ agile OOXML** (`.docx/.xlsx/.pptx`) — the ~100k-iteration spin that dominates every modern Office document |
| **MD5+RC4 key search** (`oldoffice_md5rc4`) | **Office 97/2000 40-bit RC4** (`office-keyattack --gpu`) — sweeps the 2^40 trunc keyspace on the device (a key-search kernel, not a per-password batch) |

ODF's start-key hash and Office's first hash are done per-candidate on the CPU;
the device runs the expensive loop. RAR5's check value is derived directly by
the SHA-256 kernel. The Office 97/2000 key search tests one trunc index per
work-item and re-checks any hit on the CPU.

**Why isn't *my* format accelerated?** Three reasons a scheme stays on the CPU:
it's **memory-hard or GPU-hostile** (Argon2 — KeePass KDBX4 / PuTTY v3; scrypt —
Ethereum / age / PBES2; bcrypt — OpenSSH), it has an **ambiguous profile**
(SQLCipher v3 vs v4 can't be told apart before a password verifies, and the
offload derives one profile per candidate), or **no kernel exists yet** (PDF
40-bit MD5+RC4 key-search, Office 2007 "standard" `Finish`, KeePass AES-KDF —
catalogued in [`CRACKING.md`](CRACKING.md) §4; the Office 97/2000 key search now
ships).

**Multiple GPUs / which device?** The tier enumerates every OpenCL device, ranks
them (discrete GPU > integrated GPU/APU > accelerator > CPU) across NVIDIA / AMD
/ Intel / Apple / Mesa / pocl, and splits each batch across the available
devices concurrently, with a startup batch-size autotune. `XCRACK_GPU_DEVICE`
(a case-insensitive substring of a device name or vendor) forces a specific one.
AMD GPUs and Ryzen APUs run through the OpenCL ICD.

**No GPU but want the speed elsewhere?** Offload instead: `xcrack hashline` emits
`$office$`/`$pdf$`/`$zip2$`/`$dmg$` lines for hashcat/John, and `xcrack
export-challenge` + `--resume-from` round-trips a portable challenge to any
external cracker.

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

**If the password is cached, why isn't a repeat run instant?** Because
`--found-cache` is a *candidate-ordering* cache, not a result cache: it only puts
the known password first in the stream, which skips the *wrong*-guess KDFs. Every
run still pays, per file, the one **correct-password KDF** (these are deliberately
slow — scrypt, Argon2, 100k-iteration PBKDF2, etc.; you can't derive the key
without running it once), then decrypts, recursively decomposes, and — with
`-o` — re-writes the whole extracted tree. That irreducible work is the floor
(e.g. a scrypt-based `age` file alone is hundreds of MiB of memory-hard work). To
make an actual **repeat extraction** near-instant, use **`--reuse-output`**: with
`-o DIR` it records a per-source stamp (content hash + candidate set + recovered
passwords) and on the next run skips any unchanged source entirely — no KDF, no
decrypt, no re-write (a warm `--reuse-output -o DIR samples/*` run drops from
~18s to ~0.02s). `--session FILE` similarly skips already-searched files but does
not keep the `-o` output.

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
§3 lists what is and isn't attackable — including MS Access Jet, whose password
is read straight out of the header XOR obfuscation with no cracking at all
(`access-recover`) — and the weaknesses judged not worth it.

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
`office-keyattack`, `pdf-keyattack`, `access-recover`, `version`.

**The most useful flags.**

| Need | Flag |
|------|------|
| wordlist / explicit password | `-w FILE` / `-p STR` |
| rules + masks | `--pattern FILE`, `--increment MIN:MAX`, `--hcmask FILE` |
| remember & reuse found passwords | `--found-cache FILE` / `--remember`, `--loopback` |
| resume | `--checkpoint FILE` (one file), `--session FILE` (batch) |
| triage many files | `--cost-queue`, `--fast-triage` config, `--time-limit D` |
| inspect without cracking | `--stdout`, `--keyspace`, `--benchmark`, `--estimate`, `--debug-rules`, `--show`/`--left`, `--show-config`, `--show-cache` |
| restrict candidates | `--min-length`/`--max-length`, `--encoding` |
| output & extraction | `--out DIR`, `--extract-suffix S`, `--format`, `--results-file FILE` |
| distribute | `--shard I/N`, `--server URL`, `--cluster-session FILE` |
| key-level attacks | `xcrack kp …` (incl. `kp --zip`), `xcrack office-keyattack FILE`, `xcrack pdf-keyattack FILE`, `xcrack access-recover FILE` |

Full worked examples are in [`USAGE.md`](USAGE.md).

---

## Output & extracted files

**Where do decrypted files go?** With `--out DIR`, each source's recovered tree
is written under `DIR/<source-name>.extracted/` (mirroring the nested layers),
alongside a `manifest.json` describing the tree, the recovered passwords, and
stats. Without `--out`, Xcrack reports to stdout and writes nothing.

**Can I change the `.extracted` suffix?** Yes — `--extract-suffix S` sets it
(e.g. `--extract-suffix .unpacked` → `DIR/archive.zip.unpacked/`), and `''`
gives the bare source name. It must be a single path segment (no `/` or `..`),
so it can never redirect the write outside `--out`. The config-file equivalent
is `output.extract_suffix`.

**What are the output formats?** `--format text` (a human-readable tree, the
default), `json` (one document per input: tree + passwords + stats), or `jsonl`
(one JSON object per node, stream-friendly). `--results-file FILE` also appends
a JSON manifest per input.

**Are recovered passwords ever written to logs?** No. They appear only in the
result output and the manifest; the structured log (`--log-level`) never emits a
password or plaintext.

---

## Inspecting & troubleshooting

**How do I see the settings that are actually in effect?** `--show-config`
prints the configuration after merging flags, environment, the config file and
defaults (precedence: flags > env > config > defaults), then exits without
cracking. It shows counts for explicit passwords and the cache path, never the
secret values, so it is safe to paste into a bug report.

**How do I see which passwords are cached?** `--show-cache` lists the passwords
held in the found-password cache / potfile (point it at the cache with
`--found-cache FILE`, `--remember`, or `--potfile FILE`). This differs from
`--show`, which instead reports which *files* the cache already solves.

**How do I preview an attack without running it?** `--stdout` prints the
candidate stream, `--keyspace` its size, `--benchmark` the per-file verify rate,
`--estimate` the time-to-exhaust, and `--debug-rules` per-rule hit/reject stats.
None of these decrypt anything.

**It says "not encrypted or unsupported" — now what?** Confirm the format with
`xcrack identify FILE`. For a magic-less format (e.g. SQLCipher) force it with
`--as sqlcipher`. For an `.accdb` (Access ACE) run a password search; for a Jet
`.mdb` use `xcrack access-recover`.

**A run seems stuck.** The KDF may simply be expensive (see *KDFs* above). Use
`--estimate` to see the expected time, `--progress` for a live rate/ETA, and
`--time-limit D` so a single hard file never blocks a batch.

**What do the exit codes mean?** `0` = at least one layer decrypted (or a
clean inspection), `1` = nothing decrypted / still locked, `2` = a usage or I/O
error. See [`USAGE.md`](USAGE.md#exit-codes).
