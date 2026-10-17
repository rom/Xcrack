# Xcrack FAQ

Answers grouped by topic. See also [`USAGE.md`](USAGE.md) (worked examples),
[`CRACKING.md`](CRACKING.md) (how each format is attacked),
[`FILEFORMATS.md`](FILEFORMATS.md) (the format catalogue),
[`config/README.md`](../config/README.md) (config keys), and
[`REFERENCES.md`](REFERENCES.md).

> Xcrack is a recovery / defensive tool. Use it only on files you own or are
> explicitly authorized to access.

## Index

- [Terminology and basics](#terminology-and-basics)
- [File formats](#file-formats)
- [Files and file types](#files-and-file-types)
- [Keys and key lengths](#keys-and-key-lengths)
- [Attack orchestration](#attack-orchestration)
- [Cracking alternatives (do I even need to brute force?)](#cracking-alternatives-do-i-even-need-to-brute-force)
- [Cracking methods](#cracking-methods)
- [Cracking limitations](#cracking-limitations)
- [Performance and cracking times](#performance-and-cracking-times)
- [KDFs (key-derivation functions)](#kdfs-key-derivation-functions)
- [GPU acceleration](#gpu-acceleration)
- [Ciphers and modes](#ciphers-and-modes)
- [Verification shortcuts](#verification-shortcuts)
- [Candidate generation and ordering](#candidate-generation-and-ordering)
- [Cryptanalysis](#cryptanalysis)
- [Configuration settings](#configuration-settings)
- [Command-line options](#command-line-options)
- [Output and extracted files](#output--extracted-files)
- [Inspecting and troubleshooting](#inspecting--troubleshooting)
- [Testing and validation](#testing-and-validation)
- [Documentation map](#documentation-map)

---

## Terminology and basics

**What does "crack" mean here — do you break the encryption?** No. Xcrack does
not break AES, SHA-2 or any sound primitive. It *recovers the password* (by
trying candidates against the format's own verifier) or, for a few legacy
schemes with a real weakness, recovers the *key* directly (see
[Cryptanalysis](#cryptanalysis)). Where the cipher is strong and the password is
strong, the file stays locked — that is the design, not a bug.

**Password vs. key vs. passphrase?** The **password** (or **passphrase**) is what
a human types. A **key-derivation function (KDF)** stretches it into the
symmetric **key** the cipher actually uses. Most schemes make you find the
password; a few (ZipCrypto, 40-bit Office/PDF) let you find the key without ever
learning the password. See [Keys and key lengths](#keys-and-key-lengths).

**What is a "candidate"?** One password string to test. A run streams candidates
from wordlists, rules, masks and generators, and each is checked against the
file's verifier.

**What is a "challenge"?** The small bundle of crypto material a format exposes
after a cheap probe — salt, KDF parameters, a verifier block — so candidates can
be tested without re-reading the whole file. It is also the unit Xcrack exports
for offload (`export-challenge`).

**What is "decomposition" / the result tree?** A file can nest (an encrypted
PDF inside an encrypted ZIP inside a `.tar.gz`). Xcrack peels one layer at a
time, producing a tree whose nodes are encryption layers, container layers, or
**leaves** (real content). A password that unlocks an outer layer is **promoted**
(tried first) on inner layers.

**Where's the full glossary?** [`TERMINOLOGY.md`](TERMINOLOGY.md) — engine terms,
KDFs, ciphers & modes, formats & containers, attacks & shortcuts, acceleration,
and every abbreviation/TLA used across the docs.

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

## Files and file types

**File, file type, file format, extension — what's the difference here?** Xcrack
cares about the **format** (the on-disk structure and crypto), which it reads
from the file's **content**, not its **extension**. A `.docx` renamed to `.bin`
is still detected and cracked; a `.pdf` that is really a ZIP is treated as a ZIP.
The extension is only a hint used for reporting.

**What counts as a "container" vs. an "encryption layer" vs. a "leaf"?** A
**container** holds other files and must be unpacked (ZIP, 7z, tar, an OLE2/CFB
compound file). An **encryption layer** must be decrypted with a recovered
key/password. A **leaf** is neither — real content handed back to you. One
physical file is often several layers: `report.tar.gz` → gzip (container) → tar
(container) → `secret.pdf` (encryption layer) → PDF body (leaf).

**What is a "carrier"?** A file that embeds a protected sub-object Xcrack targets
without the whole file being "the format" — e.g. a `.docm` whose `vbaProject.bin`
part carries the VBA password, or an `.eml` whose MIME attachment is the real
encrypted document. Xcrack reaches into the carrier automatically.

**Which plain (non-encrypted) wrappers does it unpack to reach an inner file?**
tar, gzip, bzip2, xz/lzma, **zstd**, **lz4**, and `.eml`/MIME. So `secret.zip`
inside `backup.tar.zst` is found and cracked without a manual unpack step.

**Why are documents treated as leaves by default?** A `.docx` is itself a ZIP of
XML parts, but exploding it into those parts is rarely what you want, so by
default a recognized document is a leaf. Opt into deeper explosion only when you
need the inner parts (see [ADR 0007](adr/0007-documents-as-leaves.md)).

**Is a huge or malformed file dangerous to point at?** No. Xcrack is built to
eat hostile input: bounded reads, a global work budget (depth, bytes, node
count, expansion ratio, time), content-hash cycle detection, and a `recover()`
guard around every format parser. A decompression bomb or a parser crash becomes
a per-node error, never a hang or a crash of the run. See
[ADR 0004](adr/0004-hostile-input-safety-budgets.md) and
[`TESTS.md`](TESTS.md).

---

## Keys and key lengths

**Is the password the key?** No. The password is stretched by a
[KDF](#kdfs-key-derivation-functions) into the cipher's key. A 6-character
password and a 256-bit AES key coexist: the password is weak, the key space is
huge, and the KDF is the bridge you pay for on every guess.

**Why does key length decide whether a "key attack" is possible?** If the
*effective* key is small enough to enumerate, you can skip the password entirely
and sweep keys. Two shipped schemes have that weakness:

- **Office 97/2000 RC4** and **PDF V1/R2 (and 40-bit R3/R4) RC4** derive a
  **40-bit** key (`MD5(…)[:5]`). 2⁴⁰ ≈ 1.1 × 10¹² keys is a feasible sweep
  (`office-keyattack`, `pdf-keyattack`), and it works regardless of how long or
  random the password was.
- **ZipCrypto** has three 32-bit internal keys recoverable from known plaintext
  (Biham–Kocher), again with no password (`kp`).

**Why can't you key-attack everything else?** Modern schemes use a **128- or
256-bit** key with no shortcut — 2¹²⁸ is not enumerable by anyone — so the only
route is to guess the password and run the KDF. AES-256, ChaCha20, and the
AES-based PDF (AESV2/AESV3) handlers are all in this group.

**What are "trunc" and "file key"?** Scheme-specific names for the small derived
key the sweep targets: the Office 97/2000 **trunc** is `MD5(UTF16LE(pw))[:5]`;
the PDF **file key** is `MD5(pad(pw)‖O‖P‖ID…)[:5]`. Both are 5 bytes = 40 bits.

**Does a longer key always mean slower cracking?** No — key *length* bounds the
key-attack route; per-guess *speed* is set by the **KDF cost**, not the key size.
A 256-bit-key file with a cheap KDF (one MD5) is far faster per guess than a
40-bit-key file would be if it used Argon2. See
[Performance and cracking times](#performance-and-cracking-times).

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

## Cracking limitations

**What can Xcrack *not* do?** It cannot break sound cryptography. If the cipher
is strong (AES, ChaCha20) and the password is strong and not reused, not in any
list, and not derivable from a rule or hint, the file stays locked — no tool
recovers it. Xcrack maximizes the chance of a *weak or reused* password being
found; it makes no dent in a genuinely strong one behind an expensive KDF.

**What is explicitly out of scope?** Online / network attacks (it only reads
local files), public-key PDF (needs the recipient's private key, not a
password), breaking the primitives themselves, and anything requiring the
cleartext you don't have. Memory-hard KDFs (Argon2, scrypt) are supported but
deliberately slow and **not** GPU-accelerated (see
[GPU acceleration](#gpu-acceleration)).

**Which formats are verify-only (no body reconstruction)?** Key/credential
stores and wallets — OpenSSH/PEM/PKCS#8 private keys, JKS, PKCS#12, PuTTY `.ppk`,
SQLCipher, KeePass, Ethereum keystore, iWork. The recovered passphrase is the
deliverable; Xcrack does not rebuild the private key or database body.

**Are any formats "staged" (recognized but not yet fully cracked)?** Yes — the
backlog in [`roadmap-enhancements.md`](roadmap-enhancements.md) tracks them with
checkboxes. Recognition and a hash-line/offload path often ship before an
in-engine cracker.

**Does it guarantee a recovered password is *the* password?** It guarantees the
candidate satisfies the format's authoritative verifier (a MAC/tag gives
cryptographic certainty; a verifier block is astronomically unlikely to collide).
In the rare unauthenticated case a second candidate could in principle also
verify; Xcrack returns the first that does.

---

## Performance and cracking times

**How fast is a crack?** It is set almost entirely by the **per-candidate KDF
cost** of the target format, not by Xcrack. Cheap verifiers run tens of
thousands of guesses per second; deliberately expensive KDFs run single digits.
Representative **single-box, pure-Go CPU** rates measured on a 4-core Intel Xeon
@ 2.10 GHz (`xcrack --benchmark`):

| Format (sample) | candidates/sec | Why |
|---|---:|---|
| JKS keystore | ~510,000 | one SHA-1 per guess |
| ZipCrypto | ~62,000 | broken stream cipher, trivial check |
| traditional PEM (MD5 `EVP_BytesToKey`) | ~93,000 | one MD5 |
| PKCS#12 | ~3,700 | modest PKCS#12 KDF |
| PKCS#8 PBES2 PEM | ~2,000 | PBKDF2, low iters |
| WinZip-AES-256 | ~1,050 | PBKDF2-HMAC-SHA1 ×1000 |
| PDF AESV3 (R6) | ~370 | iterated SHA-2 (Algorithm 2.B) |
| iWork | ~42 | PBKDF2 ×tens-of-thousands |
| RAR5 | ~40 | PBKDF2-HMAC-SHA256 |
| 7-Zip AES | ~30 | SHA-256 ×2¹⁹ |
| PuTTY `.ppk` v3 | ~9 | Argon2 (memory-hard) |
| OpenPGP (`gpg -c`) | ~6 | iterated S2K |
| OpenSSH key | ~4 | bcrypt-pbkdf |
| age (scrypt) | ~1 | scrypt (very memory-hard) |

Full methodology, more formats, attack-method comparisons and GPU/offload
figures are in [`PERFORMANCE.md`](PERFORMANCE.md). Your numbers scale with core
count (the search is near-linear) and the file's actual iteration parameters.

**How do I get the number for *my* file?** `xcrack --benchmark FILE` prints its
verify rate, `--keyspace` the candidate count, and `--estimate` the
time-to-exhaust and expected-time-to-hit — all without cracking anything:

```
$ xcrack --estimate -w list.txt secret.7z
    rate      27 candidates/sec
    keyspace  41
    time      ~1.52s to exhaust, ~760ms expected to a hit
```

**A fast format with a big keyspace can still be hopeless.** At ~62k/s a
ZipCrypto file is fast *per guess*, but an 8-char full-ASCII mask is ~6 × 10¹⁵
candidates — millennia. Speed per guess and keyspace size both matter; use
`--estimate` before committing to a mask.

**What makes a repeat run fast?** The found-password cache orders the known
password first (skipping wrong-guess KDFs), and `--reuse-output` skips an
unchanged source entirely on re-extraction. See
[Candidate generation and ordering](#candidate-generation-and-ordering).

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

**What is a "kernel"?** A small program that runs on the GPU, once per work-item
(per candidate or per key index), many thousands at a time. Xcrack ships one
kernel per accelerated primitive (e.g. `kernel_pbkdf2_sha1.cl`,
`kernel_vba_sha1.cl`). Each `.cl` file is compiled on the device at startup and
self-tested against the pure-Go reference before use.

**What is a "core"?** Here, the reusable algorithm building-block a kernel is
written around — the SHA-1, MD5 or RC4 transform. The three key-search kernels
(Office 97/2000, PDF, VBA) deliberately **reuse the same MD5/RC4/SHA-1 cores**,
so the crypto is written and validated once.

**Key-search kernel vs. batch kernel?** A **batch** kernel derives one key per
candidate password (PBKDF2, the Office spin, VBA salted-SHA-1) and the engine
checks each. A **key-search** kernel sweeps a fixed key space (the 2⁴⁰ Office and
PDF RC4 sweeps): one work-item per key index, comparing to the verifier on-device
and publishing a hit via an atomic.

**What is OpenCL?** The vendor-neutral standard Xcrack's kernels are written in
(OpenCL C). The same `.cl` runs on NVIDIA, AMD (including Ryzen APUs), Intel and
Apple GPUs through each vendor's driver (the OpenCL ICD) — no CUDA/ROCm-specific
code. Building it needs an OpenCL SDK and cgo, which is why it is behind the
`-tags opencl` build tag and off by default.

**What is pocl?** "Portable Computing Language" — an OpenCL implementation that
runs kernels on the **CPU**. Xcrack uses it as the always-available validation
device: the self-test and cross-validation tests run the real kernels on pocl in
environments with no GPU, so correctness is proven even without hardware.

**Why is it cgo / server-only and not in the CLI?** cgo + an OpenCL runtime
breaks the pure-Go, single-binary promise ([ADR 0001](adr/0001-pure-go-no-external-binaries.md)),
so the GPU tier is a hardware-gated **server** exception (`xcrackd --gpu`) that a
operator opts into. The `xcrack` CLI stays pure Go; for GPU power from the CLI,
offload via `hashline`/`export-challenge` instead.

**Which formats are accelerated today?**

| Kernel | Formats |
|--------|---------|
| PBKDF2-HMAC-SHA1 | WinZip-AES, encrypted DMG, **ODF** |
| PBKDF2-HMAC-SHA256 | **RAR5** (the 8-byte password-check derivation) |
| PBKDF2-HMAC-SHA512 | PBKDF2-SHA512 schemes |
| **Office iterated-hash spin** (SHA-1/256/384/512) | **Office 2010+ agile OOXML** (`.docx/.xlsx/.pptx`) — the ~100k-iteration spin that dominates every modern Office document |
| **MD5+RC4 key search** (`oldoffice_md5rc4`) | **Office 97/2000 40-bit RC4** (`office-keyattack --gpu`) — sweeps the 2^40 trunc keyspace on the device (a key-search kernel, not a per-password batch) |
| **RC4 key search** (`pdf_rc4keysearch`) | **PDF 40-bit RC4** (`pdf-keyattack --gpu`) — sweeps the 2^40 file-key space (V1/R2 and 40-bit R3/R4) on the device; RC4-only, the one per-document MD5 is precomputed on the host |
| **Salted SHA-1 batch** (`vba_sha1`) | **MS VBA project** password (`SHA1(pass‖salt)`, hashcat's `sha1($pass.$salt)` / mode 110) — a whole candidate batch hashed per dispatch |

ODF's start-key hash and Office's first hash are done per-candidate on the CPU;
the device runs the expensive loop. RAR5's check value is derived directly by
the SHA-256 kernel. The Office 97/2000 and PDF key searches test one key index
per work-item and re-check any hit on the CPU. The VBA salted-SHA-1 is a single
un-iterated hash, so the device just bulk-computes the batch and the CPU
re-checks only an apparent hit.

**Why isn't *my* format accelerated?** Three reasons a scheme stays on the CPU:
it's **memory-hard or GPU-hostile** (Argon2 — KeePass KDBX4 / PuTTY v3; scrypt —
Ethereum / age / PBES2; bcrypt — OpenSSH), it has an **ambiguous profile**
(SQLCipher v3 vs v4 can't be told apart before a password verifies, and the
offload derives one profile per candidate), or **no kernel exists yet** (Office
2007 "standard" `Finish`, KeePass AES-KDF — catalogued in
[`CRACKING.md`](CRACKING.md) §4; the Office 97/2000 and PDF 40-bit key searches
now ship).

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

---

## Testing and validation

**How is Xcrack tested?** Across the three modules there are ~140 test files and
~370 unit tests, ~30 fuzz targets, plus the `-tags opencl` GPU suite. Every
cryptographic scheme is **cross-validated against an independent oracle** before
it ships. Full detail — categories, oracles, the CI gate — is in
[`TESTS.md`](TESTS.md).

**What are the "oracles"?** Real third-party tools and libraries whose output a
scheme must reproduce byte-for-byte: qpdf (PDF), msoffcrypto-tool (legacy
Office), pykeepass + KeePassXC (KeePass), LibreOffice (ODF), Apple Pages/Numbers/
Keynote (iWork), the `age` and GnuPG CLIs, `rar`/`7z` (header-encrypted
archives), bkcrack (ZipCrypto known-plaintext), jackcess (Access Jet), the
phc-winner-argon2 reference, and hashcat's canonical example hashes. Their
fixtures are committed in-tree (indexed in [`gold/README.md`](../gold/README.md))
so the cross-validation stays reproducible even if a source disappears.

**What does the fuzzing cover?** Every hostile-input parser (PDF, CFB/OLE2, ZIP,
7z/RAR, Office, ODF, key stores, the mask/rule compiler) and the whole recursive
engine (`FuzzProcess`). CI replays the committed seed corpora and regression
crashers deterministically on every run; a nightly job does timed exploratory
fuzzing.

**What stops a malicious file from hanging or crashing a run?** A global work
budget (depth, total bytes, node count, expansion ratio, time), content-hash
cycle detection, bounded readers, and a `recover()` guard around every format
call — all exercised by dedicated bomb/fan-out/cycle tests. See
[ADR 0004](adr/0004-hostile-input-safety-budgets.md).

**Does CI build the GPU path?** No. CI runs build, `go vet`, a `gofmt` check,
the `-race` test suite, a deterministic fuzz-corpus replay, and (non-blocking)
`govulncheck` — all on the pure-Go default build. The `-tags opencl` kernels are
validated separately on pocl (CPU OpenCL) and never built by CI, per
[ADR 0001](adr/0001-pure-go-no-external-binaries.md). `make check` runs the same
gate locally.

---

## Documentation map

**Where do I start?** [`USAGE.md`](USAGE.md) — build, run the CLI and the
`xcrackd` service, embed the library, and configure everything, with worked
examples. The docs index is [`docs/README.md`](README.md).

**Which doc answers what?**

| Doc | Covers |
|---|---|
| [`USAGE.md`](USAGE.md) | commands, flags, config, library/service, end-to-end examples |
| [`FILEFORMATS.md`](FILEFORMATS.md) | every supported format/variant, detection, verifier/KDF/cipher, its oracle |
| [`CRACKING.md`](CRACKING.md) | how each format is attacked; verification shortcuts & cryptanalysis; what the GPU tier accelerates |
| [`FAQ.md`](FAQ.md) | this file — quick answers by topic |
| [`TERMINOLOGY.md`](TERMINOLOGY.md) | the glossary (engine, KDFs, ciphers, formats, attacks, acceleration, TLAs) |
| [`PERFORMANCE.md`](PERFORMANCE.md) | per-format cost, measured rates, attack-method and platform guidance |
| [`TESTS.md`](TESTS.md) | the test suite: categories, oracles, fuzzing, the CI gate |
| [`REFERENCES.md`](REFERENCES.md) | the crypto, cryptanalysis and attack methods used, with primary sources |
| [`CHANGELOG.md`](CHANGELOG.md) | notable changes, grouped by pull request |
| [`roadmap.md`](roadmap.md) / [`roadmap-enhancements.md`](roadmap-enhancements.md) | phased plan and the checkbox backlog (features, approaches, formats) |
| [`architecture.md`](architecture.md) / [`design.md`](design.md) / [`asr.md`](asr.md) | system views, APIs/algorithms, quality attributes |
| [`threat-model.md`](threat-model.md) / [`adr/`](adr/) | trust boundaries; the significant decisions |

**Is there a glossary for the jargon?** Yes — [`TERMINOLOGY.md`](TERMINOLOGY.md)
defines every engine concept, KDF, cipher/mode, format, attack and abbreviation
used across these docs.
