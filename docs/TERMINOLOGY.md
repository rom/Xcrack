# Xcrack — Terminology & Glossary

A reference for the vocabulary used across the Xcrack docs and code: the engine's
own concepts, the cryptographic primitives and ciphers it works against, the file
formats and containers it understands, the attacks and shortcuts it brings to
bear, and the abbreviations and three-letter acronyms (TLAs) that recur
throughout.

It is a companion to the reference documents — [`CRACKING.md`](CRACKING.md)
(how each format is attacked), [`FILEFORMATS.md`](FILEFORMATS.md) (what is
detected and parsed), [`PERFORMANCE.md`](PERFORMANCE.md) (cost and speed), and
[`REFERENCES.md`](REFERENCES.md) (primary sources). When a term is explained in
depth elsewhere, the entry points there.

Within every table the terms are ordered **A–Z** (entries beginning with a digit
sort first). Case is ignored for ordering.

> Authorized use only. Xcrack is a recovery/defensive tool: operate on files you
> own or are explicitly permitted to access.

---

## 1. Engine, recursion & result model

The core vocabulary of Xcrack's recursive-decomposition engine (see
[`design.md`](design.md) and [ADR 0003](adr/0003-recursive-decomposition-model.md)).

| Term | Meaning |
| ---- | ------- |
| **Adaptive scheduling** | Dispatching the smallest/weakest targets first and reusing any recovered password across the whole run (`--adaptive`). |
| **Budget / limits** | The caps (depth, total bytes, node count, compression ratio, time) that bound work and defeat decompression bombs (see [ADR 0004](adr/0004-hostile-input-safety-budgets.md)). |
| **Candidate** | A single password string to test against a file. |
| **Carrier** | A file that embeds the protected object Xcrack targets without the whole file being "the format" — a `.docm` whose `vbaProject.bin` holds the VBA password, an `.eml` whose attachment is the real encrypted document. |
| **Challenge** | The crypto material (salt, verifier, KDF parameters) a format exposes so candidates can be tested without re-reading the whole file. The portable form is the **challenge envelope** (JSON exported with `xcrack export-challenge`, consumed by an external cracker or `--resume-from`). |
| **Checkpoint** | Saved progress of one long single-file search, resumed with `--checkpoint FILE`. |
| **Cluster** | A fleet of `xcrackd` workers a search fans out to — *collective* (many servers, one file) or *partition* (server groups on different files). |
| **Confidence** | The 0–1 score a format returns from a bounded head peek; `DetectAll` ranks formats by it and picks the best. |
| **Container layer** | A file (or entry) that holds other files (an archive or compound document) and must be unpacked. |
| **Context / association candidates** | Guesses derived from the node's name and cleartext harvested from plain sibling entries, tried before the general keyspace. |
| **Cost queue** | Benchmarking each file and attacking the fastest/weakest schemes first (`--cost-queue`). |
| **Cycle detection** | A content-hash guard that stops a quine/loop (a container that contains itself) from recursing forever. |
| **Decompose / decomposition** | Unpacking a container (or exploding a document) into child entries the engine then re-detects and recurses into. |
| **Detection** | Choosing a format by **content** (magic bytes / structure), not by file extension — so an encrypted file inside an archive is handled correctly however its entry is named. |
| **Document explosion** | The opt-in `--explode-documents` mode that decomposes an Office document (OOXML/OLE) into its internal parts so the engine recurses into each, instead of treating the document as an opaque leaf ([ADR 0007](adr/0007-documents-as-leaves.md)). |
| **Encryption layer** | A file (or entry) that is password-protected and must be decrypted. |
| **Explodable** | A format capability: a document that can be decomposed into its internal parts (see Document explosion). |
| **Fast-reject** | An even cheaper 1–2 byte check tried *before* the KDF runs, to discard most wrong guesses; the authoritative verifier is always re-run on anything it passes, so it can never cause a false positive. |
| **File jobs** | The number of files cracked concurrently, each with its own candidate stream (`--file-jobs`); output stays in argument order. |
| **Format** | A plugin that recognizes one file type. May be `Encrypted` (has a KDF/verifier), a `Container` (unpacks to entries), `Explodable` (a document decomposable into parts), `Accelerable` (exposes a batchable KDF for the GPU), or several at once. |
| **Hint** | A per-file signal tried early — an embedded one (iWork `.iwph`, a ZIP comment) or a supplied `--hint STR`. |
| **Keyspace** | The number of candidates a configured attack will produce; reported by `--keyspace`. |
| **Leaf** | A node that is neither encrypted nor a container: real content handed back to the caller. |
| **Loopback** | Re-feeding already-recovered passwords back through the rule engine as fresh candidates (`--loopback`), a hashcat idiom. |
| **Manifest** | The `manifest.json` written alongside an extracted tree: the per-node format, password, and content hashes. |
| **Node** | One position in the decomposition tree — a file at some depth, with its format, the password that unlocked it (if any), its content, and its children. |
| **Password promotion** | Trying a password that unlocked an outer layer first on inner layers, since nested packaging reuses passwords. Corpus-wide promotion across unrelated files is `--adaptive`. |
| **Potfile / found-password cache** | A persistent file of recovered passwords (`--found-cache` / `--remember`, hashcat-style "pot") whose entries lead the candidate stream so a reused password is recovered instantly next run. |
| **Probe** | The one-time step that reads a file's salt, iteration count and verifier into a `Challenge`, done once per file before any candidate is tried. |
| **Registry** | The explicit set of registered formats the engine consults; `DetectAll` ranks every format's confidence against a file's leading bytes and picks the best. |
| **Reuse-output** | A per-source stamp (content hash + candidate set + recovered passwords) under `-o DIR` that lets `--reuse-output` skip an unchanged source entirely on a repeat run — no KDF, no decrypt, no re-write. |
| **Session** | Saved progress of a whole multi-file batch, resumed with `--session FILE` (finished files skipped). |
| **Shard** | A disjoint `I/N` stride of the keyspace handed to one worker (`--shard I/N`) so a search can be split across processes or machines. |
| **Status (node)** | A node's outcome — Decrypted, Locked (still encrypted, not found), LimitExceeded (a budget stopped it), or Error (a guarded parser failure). |
| **Verifier** | The cheap pass/fail check that distinguishes a wrong password from a right one without decrypting the whole body (a 2-byte value, an HMAC, a padding check). |

## 2. Key derivation & hashing

How a password becomes a key, and the hashing that underlies it. See
[`REFERENCES.md`](REFERENCES.md) §1 for the standards.

| Term | Meaning |
| ---- | ------- |
| **AES-KDF** | KeePass's iterated AES-256-ECB key-stretch (KDBX3.1, optional in KDBX4); GPU-accelerable because the seed is shared across candidates. |
| **Argon2** (d / i / id) | The memory-hard, Password-Hashing-Competition-winning KDF (KeePass KDBX4, PuTTY v3). Memory-hardness makes it GPU-hostile — Xcrack keeps it on the CPU. |
| **bcrypt / bcrypt-pbkdf** | A Blowfish-based password hash; `bcrypt-pbkdf` keys OpenSSH private keys. GPU-hostile. |
| **BLAKE2** | A fast modern hash (BLAKE2b inside Argon2; BLAKE2s-256 is a newer VeraCrypt option). |
| **Composite key** | KeePass's combined secret (password [+ keyfile + Windows-account data]) hashed together before the KDF (AES-KDF or Argon2) runs. |
| **DK / dkLen** | Derived Key and its length in bytes — a KDF's output and requested size. |
| **EVP_BytesToKey** | OpenSSL's legacy MD5-based password→key+IV routine (traditional `DEK-Info` PEM); a single cheap hash, so very fast to attack. |
| **HMAC** | Hash-based Message Authentication Code (RFC 2104): a keyed hash construction, the PRF inside PBKDF2 and a common verifier. |
| **KDF** (Key Derivation Function) | The function that turns a password (+ salt + parameters) into a cryptographic key. Deliberately slow KDFs are the main obstacle to a password search. |
| **Keccak-256 / SHA-3** | The Keccak hash (SHA-3 family; the Ethereum MAC uses pre-standard-padding Keccak-256). |
| **MD5 / SHA-1 / SHA-256 / SHA-512** | Message-digest / Secure-Hash-Algorithm hash functions used as KDF/verifier building blocks across the formats. |
| **Memory-hard** | A KDF property (Argon2, scrypt) requiring a large memory region per guess, which defeats the cheap massive parallelism of GPUs/ASICs — so these stay on the CPU. |
| **PBES2** | PKCS#5 v2 Password-Based Encryption Scheme: PBKDF2 (or scrypt) to a key, then a block cipher (encrypted PKCS#8 keys). |
| **PBKDF2** | Password-Based KDF 2 (RFC 8018): HMAC iterated a set number of times. Xcrack meets it with HMAC-SHA1/-SHA256/-SHA512; the GPU tier's primary accelerated step. |
| **PRF** (Pseudo-Random Function) | The keyed function a KDF iterates (for PBKDF2, an HMAC); the engine's `AccelKDF` carries a PRF selector so the right GPU kernel is chosen. |
| **RIPEMD-160** | A legacy 160-bit hash (TrueCrypt/VeraCrypt header KDF option, some wallets). |
| **S2K** (String-to-Key) | OpenPGP's password-to-key conversion; the iterated-salted mode (`gpg -c`) is a cheap iterated hash. |
| **Salt** | Random per-file (or per-entry) bytes mixed into the KDF so the same password yields different keys and precomputed tables don't apply. A KDF missing a salt (PDF R5, §5) is much weaker. |
| **scrypt** | A memory-hard KDF parameterized by `N, r, p` (age, Ethereum keystore, some PBES2). Like Argon2, deliberately CPU-bound for a cracker. |
| **Spin / iteration count** | The number of KDF repetitions (Office agile's ~100 000 iterated-hash **spin**, PBKDF2's iteration count); always *read from the file*, never assumed. |
| **Start key / pre-hash** | A format-specific hash applied to the password *before* the main KDF (ODF's SHA-256/SHA-1 start key); carried per-candidate on the CPU via `AccelKDF.PreHash` when the main spin is offloaded. |
| **Transform seed / rounds** | KeePass AES-KDF parameters — the random seed the password is AES-encrypted under, repeated `rounds` times. |
| **UTF-16LE / UTF-16BE** | Little-/big-endian UTF-16 encodings a password is hashed in by some formats — `MD5(UTF16LE(pw))` (Microsoft), `UTF16BE(pw)` (JKS). |
| **Work factor (cost parameter)** | The tunable that sets a KDF's expense — scrypt `N`/`r`/`p`, Argon2 time/memory/parallelism, PBKDF2/AES-KDF iteration count. |

## 3. Ciphers, modes & authentication

The bulk ciphers and the modes/MACs wrapped around them.

| Term | Meaning |
| ---- | ------- |
| **AEAD** | Authenticated Encryption with Associated Data: encryption that also authenticates, so a wrong key fails the tag (GCM, ChaCha20-Poly1305). |
| **AES** | Advanced Encryption Standard, the dominant block cipher (128/192/256-bit keys) across modern formats. |
| **Block cipher** | A cipher over fixed-size blocks (AES, 3DES, Blowfish); used through a mode (CBC/CTR/…). |
| **Blowfish / 3DES** | Legacy block ciphers (Blowfish underlies bcrypt; 3DES unwraps the DMG v1 key). |
| **CBC** (Cipher Block Chaining) | A block-cipher mode where each block is XORed with the previous ciphertext; needs an IV and padding. |
| **CFB** (Cipher Feedback) | A self-synchronizing stream mode (OpenPGP's SEIPD packet). *Not to be confused with CFB the compound-file container — see §4.* |
| **ChaCha20-Poly1305** | The AEAD stream cipher + MAC used by `age`. |
| **CTR** (Counter) | A mode that turns a block cipher into a stream cipher by encrypting a counter (WinZip-AES, PDF AESV3). |
| **ECB** (Electronic Codebook) | The mode-less block mode (each block independent); used inside OOXML standard and the AES-KDF stretch, not for bulk data. |
| **GCM** (Galois/Counter Mode) | An AEAD mode: CTR encryption plus an authentication tag (ODF 1.3's authenticated variant). |
| **IV / nonce** | Initialization Vector / number-used-once — the non-secret per-message value a mode needs; reuse under one key is what breaks ZipCrypto cross-entry and the Office keystream-reuse weakness. |
| **Key schedule** | The expansion of a key into per-round (or per-block) subkeys; ZipCrypto's three 32-bit keys are its (invertible) schedule. |
| **Key wrap / KEK** | Encrypting one key under a Key-Encryption-Key (the DMG unwraps its AES data key with a derived KEK via 3DES/AES key-wrap). |
| **MAC** | Message Authentication Code — a keyed integrity tag (HMAC, the PKCS#12 MacData, the Ethereum Keccak MAC); often doubles as the verifier. |
| **MDC** (Modification Detection Code) | OpenPGP's SHA-1 integrity trailer inside a SEIPD packet, used as a second verifier after the 2-byte CFB quick-check. |
| **Padding (PKCS#7)** | The block-filling scheme CBC needs; a malformed unpad after decryption is itself a cheap wrong-key verifier. |
| **Poly1305** | The one-time MAC paired with ChaCha20 in the age AEAD. |
| **RC4** | A legacy stream cipher (legacy Office, PDF RC4 revisions). Weak, and the lever for the 40-bit key attacks. |
| **Stream cipher** | A cipher producing a keystream XORed with the data (RC4, ChaCha20, ZipCrypto, any block cipher in CTR/CFB). |
| **XTS** | A block-cipher mode for disk sectors (full-volume encryption — roadmap, §5 of the enhancement backlog). |
| **ZipCrypto / PKWARE** | The traditional ZIP stream cipher (bespoke 3×32-bit key schedule): cryptographically broken (see §5). |

## 4. File formats, containers & key stores

The on-disk structures Xcrack recognizes (or has on the roadmap). The full
catalogue with detection and cross-validation is in
[`FILEFORMATS.md`](FILEFORMATS.md).

| Term | Meaning |
| ---- | ------- |
| **7-Zip** (`.7z`) | SHA-256-iterated AES-256 archive; optionally header-encrypted (`-mhe=on`), where even the file list is encrypted. |
| **age** | A modern file-encryption format; the passphrase mode is scrypt + ChaCha20-Poly1305. ASCII-armored input (`age -a`) is de-armored transparently. |
| **ASCII armor** | A Base64 + checksum text wrapper around binary crypto (`-----BEGIN…`): OpenPGP (CRC-24) and age armor; de-armored before parsing. |
| **Berkeley DB** | The key/value container holding a Bitcoin Core `wallet.dat` (roadmap). |
| **BitLocker / VeraCrypt / LUKS / FileVault** | Full-volume encryption formats (Windows / cross-platform / Linux / macOS) — roadmap, DFIR-critical, threat-review-gated. |
| **CAB / MSI / NSIS** | Windows installer/cabinet containers (MSI is an OLE2/CFB compound file) — roadmap unpack-and-recurse targets. |
| **DMG** | Apple disk image; the encrypted `encrcdsa` v1/v2 forms use PBKDF2-HMAC-SHA1 to unwrap an AES-128/256 key. |
| **DPB** | The field of a VBA `PROJECT` stream that stores the project password — MS-OVBA "Data Encryption" (reversible) wrapping a plaintext password or a `SHA1(pw‖4-byte salt)` hash. |
| **EncryptionInfo / EncryptedPackage** | The two streams of an encrypted OOXML document inside its OLE/CFB wrapper: the crypto descriptor and the ciphertext package. |
| **Ethereum keystore** (Web3 Secret Storage) | The geth/MetaMask/MyEtherWallet JSON wallet — scrypt or PBKDF2-HMAC-SHA256 → key, verified by a Keccak-256 MAC. |
| **iWork** | Apple Pages/Numbers/Keynote — a ZIP whose `.iwpv2` verifier is PBKDF2 → AES-128; carries an embedded password **hint** (`.iwph`). |
| **Jet / ACE** | Microsoft Access database engines — **Jet** (`.mdb`, Access 97–2003) stores the password XOR-obfuscated (recoverable with no cracking); **ACE** (`.accdb`, 2007+) uses a real Office-style KDF. |
| **JKS** | Java KeyStore — a SHA-1 integrity digest over `UTF16BE(password)` + a fixed phrase + the store body. |
| **KDBX** | The KeePass database format — **KDBX3.1** (AES-KDF) and **KDBX4** (Argon2d/id or AES-KDF). |
| **Keybag** | The iOS/iTunes backup key container (Manifest.plist + `Manifest.db`), passphrase-gated (roadmap). |
| **Magic** | The fixed leading bytes that identify a format (`PK\x03\x04` for ZIP, `28 B5 2F FD` for zstd). |
| **MBCS** | Multi-Byte Character Set — the code-page byte encoding a password is hashed in for the VBA project hash (ASCII passwords are unchanged). |
| **MIME / `.eml`** | The email container; its Base64/quoted-printable attachments are decoded and handed to their own formats. |
| **ODF** (OpenDocument Format) | LibreOffice/OpenOffice `.odt/.ods/.odp`: a ZIP with PBKDF2-HMAC-SHA1 + AES-256-CBC (or authenticated -GCM in 1.3). |
| **OLE2 / CFB** (Compound File Binary) | Microsoft's "compound file" container (a FAT-like filesystem in a file) holding legacy `.doc/.xls/.ppt` streams, the encrypted-OOXML package, and MSI/HWP bodies. *CFB here is the container, distinct from CFB the cipher mode in §3.* |
| **OOXML** (Office Open XML) | The modern `.docx/.xlsx/.pptx` family — a ZIP of XML parts; encrypted ones are an OLE/CFB wrapper around the ZIP. |
| **PDF** | Portable Document Format; its encryption **revisions** R2–R6 span 40-bit RC4 to AES-256 (see §5 and [`CRACKING.md`](CRACKING.md)). |
| **PKCS#8 / PEM** | Private-key encodings; PEM is the Base64 "`-----BEGIN…`" armor, PKCS#8 the key structure (PBES2 = PBKDF2/scrypt, or legacy `EVP_BytesToKey`). |
| **PKCS#12** (`.p12`/`.pfx`) | The RFC 7292 key-store format; verified by its MacData HMAC independently of bag encryption. |
| **PPK** | PuTTY Private Key file — Argon2 (v3) or SHA-1 (v2) with a Private-MAC verifier. |
| **RAR4 / RAR5** | RAR archive encryption — RAR5 is PBKDF2-HMAC-SHA256 with an 8-byte password-check value; both support header encryption (`-hp`). |
| **SEIPD** | OpenPGP's Symmetrically-Encrypted-Integrity-Protected-Data packet (`gpg -c` output, CFB + MDC). |
| **Skippable frame** | A zstd frame (magic `50..5F 2A 4D 18`) carrying out-of-band metadata that a decoder passes over — detected so a zstd stream that leads with one is still recognized. |
| **SQLCipher** | Encrypted SQLite — PBKDF2-HMAC-SHA512 ×256k (v4) or -SHA1 ×64k (v3), page-1 HMAC verifier. |
| **tar / gzip / bzip2 / xz** | Plain (non-encrypted) Unix container + compressors, unpacked to reach an encrypted file wrapped inside. |
| **VBA** | Visual Basic for Applications — Office macro streams (MS-OVBA). The **project-protection password** (the IDE "lock project for viewing" lock) is recovered by `vba-recover` / `--as vbaproject`; the macro source itself is never encrypted. |
| **WinZip-AES** (AE-1 / AE-2) | ZIP's AES extension (extra field `0x9901`): PBKDF2-HMAC-SHA1 ×1000 + AES-CTR + HMAC-SHA1. **AE-2** omits the CRC that **AE-1** keeps (the AE-1 CRC leak is a plaintext-only weakness, §5). |
| **ZipCrypto** | ZIP's legacy encryption (see §3/§5). |
| **zstd / lz4 / brotli** | Modern single-stream compressors wired as containers (zstd/lz4 ship; brotli is roadmap) — so `.tar.zst` / `.tar.lz4` and the encrypted file inside are reached. |

## 5. Attacks, cryptanalysis & shortcuts

What is tried, and the structural weaknesses Xcrack exploits (or documents). The
authoritative, per-format treatment is [`CRACKING.md`](CRACKING.md) §3.

| Term | Meaning |
| ---- | ------- |
| **Association attack** (hashcat `-a 9`) | A hint bound 1:1 to a specific target (a username/filename per hash); deferred in Xcrack — the broad `--hint`/`--context` cover the file-content case. |
| **Biham–Kocher** | The 1994 known-plaintext attack on ZipCrypto's stream cipher; recovers the 96-bit internal state with no password. Implemented in-tree (`xcrack kp`) with an optional **bkcrack** offload. |
| **Brute force** | Exhaustively trying a keyspace (all strings of a length/charset). The fallback when no better candidate order exists. |
| **Combinator** | Concatenating two wordlists (hashcat `-a 1`). |
| **Cross-entry key reuse** | Because every ZipCrypto entry shares one password-derived key state, one recovery decrypts the whole archive with no further search. |
| **Dictionary / wordlist attack** | Trying entries from a list of likely passwords, optionally rule-mangled — almost always the highest-yield attack. |
| **Fingerprint attack** | hashcat's hybrid of substring extraction + combination; not implemented (Markov/PCFG + rules cover the niche). |
| **Hashcat brain** | A networked server that rejects already-tried candidates across a whole cluster; Xcrack has `--cluster-session` cross-run dedup, not a live shared reject (roadmap). |
| **Hybrid** | A wordlist with a mask appended or prepended (hashcat `-a 6/7`). |
| **Incremental mode** | John the Ripper's statistics-driven "smart brute force"; Xcrack's analogue is Markov/PCFG generation. |
| **KAT** (Known-Answer Test) | A fixed input→output vector used to cross-validate a scheme against an external oracle. |
| **Key attack** | Sweeping the *key* space directly when the password collapses to a short key — the 40-bit RC4 attacks on Office 97/2000 (`office-keyattack`) and PDF V1/R2 (`pdf-keyattack`). |
| **Keyboard walk** | Generating candidates from adjacent-key paths on a keyboard (`qwerty`, `1qaz2wsx`). |
| **Keystream reuse / two-time pad** | Encrypting two messages with the same keystream (same key+IV) lets their XOR cancel the keystream and leak plaintext (the Office RC4 re-save weakness, Wu 2005) — recovers plaintext, not the password. |
| **KPA** (Known-Plaintext Attack) | Recovering key material from known plaintext rather than the password. For ZipCrypto, ~12 known plaintext bytes recover the internal key state. |
| **Markov** | Letter-transition-probability ordering/generation (Narayanan–Shmatikov), so likelier strings are tried first (`--order markov`, `--markov`). |
| **Mask** | A per-position charset template (hashcat `?l?u?d?s`) describing a structured keyspace. |
| **Oracle** | The independent, trusted implementation (a real CLI, a published vector) a scheme's output is checked against. |
| **PCFG** | Probabilistic Context-Free Grammar — Weir et al.'s structure-learned candidate generation (`--pcfg`). |
| **PRINCE** | PRobability INfinite Chained Elements — Jens Steube's chained-word generator. |
| **Rainbow table** | A time-memory-trade-off lookup table of hash→preimage chains (Oechslin 2003); the precompute route to instant recovery (Ophcrack for LM, Elcomsoft "Thunder Tables" for 40-bit Office) — roadmap for Xcrack's 40-bit sweeps. |
| **Reduced known-plaintext** (Stay 2001) | Michael Stay's reduction of the ZipCrypto KPA to as little as 2–3 known bytes in many cases — documented, not built (Xcrack needs the keys, not the password, and ~12 bytes of compressed plaintext is nearly always available). |
| **Rule** | A per-word transform (append, capitalize, leet-substitute, …) in the hashcat rule language; Xcrack implements the full function + reject set. |
| **Single crack mode** | John the Ripper's fast first pass that mangles the username/GECOS fields; Xcrack's analogue is the context/hint candidates. |
| **Slow candidates** (hashcat `-S`) | Generating candidates on the CPU so complex generators can feed a GPU search; Xcrack already generates on the CPU and offloads only the KDF. |
| **Spray / breach corpus** | Trying a few very common passwords across many targets (spray), or a frequency-ordered leaked-password list (breach). |
| **TMTO / Thunder Tables** | Time-Memory Trade-Off (Hellman 1980; Oechslin rainbow tables 2003); Elcomsoft's precomputed-table product name for instant 40-bit key recovery. |
| **Toggle-case** | A generator/rule enumerating upper/lower combinations of a word's letters. |
| **VelvetSweatshop / empty password** | Fixed/empty keys that unlock documents with zero real search — Excel's read-only `VelvetSweatshop`, and the empty **user** password that opens owner-restricted PDFs of every revision. |
| **Verification shortcut** | Any way to test or recover a key more cheaply than running the full KDF per candidate (a fast verifier, a header check value, a key attack, or a no-crack decode like the Access Jet header). |
| **Weak-RNG "guaranteed recovery"** (Stay 2001) | Legacy WinZip ≤8.0 / NetZip generated the 12-byte encryption header with MSVC `rand()` (a 31-bit seed), so the key state is recoverable with **no** known plaintext when an archive has ≥5 encrypted entries — documented as staged (niche legacy archivers, no obtainable oracle fixture). |

## 6. Acceleration & operations

| Term | Meaning |
| ---- | ------- |
| **Autotune / optimal batch** | The startup micro-benchmark that picks the per-dispatch candidate-batch size for the device(s) (`BatchTuner.OptimalBatch`), scaled by device count. |
| **Batch kernel** | A GPU kernel that derives one key per candidate password (PBKDF2, the Office spin, VBA salted-SHA-1); the engine checks each returned digest/key. |
| **Core (crypto core)** | The reusable algorithm building-block a kernel is written around — the MD5, RC4 or SHA-1 transform; the key-search kernels deliberately share cores. |
| **Device rank** | The selection score for automatic device choice: discrete GPU > integrated GPU/APU > accelerator > CPU, with compute units breaking ties. |
| **Fast mode** | (Claude Code) an output-speed option, unrelated to Xcrack cracking. |
| **FPGA / ASIC** | Fixed-function hardware accelerators used by some commercial crackers; out of scope for Xcrack (OpenCL on GPUs only). |
| **GPU tier** | The opt-in, hardware-gated OpenCL acceleration in `xcrackd` (`-tags opencl`, `--gpu`) that batches the KDF/key-sweep onto a device; never in the pure-Go default or CI ([ADR 0001](adr/0001-pure-go-no-external-binaries.md) amendment). |
| **Hash-line / `*2john`** | A one-line text encoding of a file's crypto parameters (`$office$`, `$pdf$`, `$zip2$`, `$dmg$`) for offloading to **hashcat** / **John the Ripper** (JtR). |
| **Kernel** | A program compiled to run on the GPU, once per work-item (per candidate or key index), thousands in parallel; self-tested against the Go reference at startup. |
| **Key-search kernel** | A GPU kernel that sweeps a fixed key space (the 2⁴⁰ Office/PDF RC4 sweeps): one work-item per key index, comparing to the verifier on-device and publishing a hit via an atomic. |
| **Metrics / Prometheus** | The observability endpoint `xcrackd` exposes (candidate rate, throughput, per-scheme counters). |
| **OpenCL** | The vendor-neutral compute API the GPU kernels are written in; runs on NVIDIA/AMD/Intel/Apple through each vendor's **ICD** (Installable Client Driver). |
| **pocl** | Portable Computing Language — a CPU OpenCL implementation used to validate the GPU path in CI-less containers (correct, but no speed-up). |
| **Resource manager / agent** | A distributed-cracking orchestrator (the commercial suites' and Hashtopolis's model); Xcrack's equivalent is the `xcrackd` cluster + `--cluster-session` (a managed UI is roadmap). |
| **ROCm / HIP / CUDA** | AMD's (ROCm/HIP) and NVIDIA's (CUDA) native compute stacks — a documented future back-end; the OpenCL kernels already run on those GPUs via the ICD. |
| **Work-item / work-group** | OpenCL's unit of parallel execution (one kernel invocation) / a scheduled bundle of them. |

## 7. Abbreviations & TLAs

A quick-reference index of the acronyms used across the docs (expanded in context
above).

| Abbrev. | Expansion |
| ------- | --------- |
| **ADR** | Architecture Decision Record |
| **AE-1 / AE-2** | WinZip AES encryption variants (AE-1 keeps the CRC, AE-2 omits it) |
| **AEAD** | Authenticated Encryption with Associated Data |
| **AES** | Advanced Encryption Standard |
| **APFS** | Apple File System (FileVault2 volume format) |
| **API** | Application Programming Interface |
| **ASIC** | Application-Specific Integrated Circuit |
| **ASR** | Architecturally Significant Requirement |
| **BDB** | Berkeley DB (Bitcoin `wallet.dat` container) |
| **BKS / JCEKS** | Bouncy Castle KeyStore / Java Cryptography Extension KeyStore |
| **CAB** | Microsoft Cabinet (installer container) |
| **CBC / CTR / ECB / GCM / CFB / XTS** | block-cipher modes (§3) |
| **CFB** | Cipher Feedback (mode) **or** Compound File Binary (container) — disambiguate by context |
| **CLI** | Command-Line Interface |
| **CRC** | Cyclic Redundancy Check (CRC32 is ZipCrypto's content verifier) |
| **CSPRNG / RNG** | (Cryptographically-Secure) Random Number Generator |
| **CTF** | Capture The Flag (security competition) |
| **CUDA** | Compute Unified Device Architecture (NVIDIA) |
| **DEK / KEK** | Data Encryption Key / Key Encryption Key |
| **DFIR** | Digital Forensics & Incident Response |
| **DK** | Derived Key |
| **DMCA** | Digital Millennium Copyright Act (the law behind the Sklyarov case) |
| **DRM** | Digital Rights Management |
| **FDE** | Full-Disk Encryption |
| **FPGA** | Field-Programmable Gate Array |
| **GPU / CPU** | Graphics / Central Processing Unit |
| **HIP** | Heterogeneous-compute Interface for Portability (AMD) |
| **HMAC** | Hash-based Message Authentication Code |
| **HWP / HWPX** | Hangul Word Processor document (binary / ZIP-XML) |
| **ICD** | Installable Client Driver (OpenCL) |
| **IV** | Initialization Vector |
| **JtR** | John the Ripper (password cracker) |
| **KAT** | Known-Answer Test |
| **KDF** | Key Derivation Function |
| **KPA** | Known-Plaintext Attack |
| **LUKS** | Linux Unified Key Setup (full-volume encryption) |
| **MAC** | Message Authentication Code |
| **MBCS** | Multi-Byte Character Set |
| **MDC** | Modification Detection Code (OpenPGP) |
| **MITM** | Man-In-The-Middle |
| **MVP** | Minimum Viable Product |
| **NSIS** | Nullsoft Scriptable Install System (installer) |
| **OLE** | Object Linking & Embedding (OLE2 = the compound-file container) |
| **OOXML** | Office Open XML |
| **OPAL / SED** | TCG Opal self-encrypting-drive standard / Self-Encrypting Drive |
| **PBE** | Password-Based Encryption |
| **PBES2 / PBKDF2** | Password-Based Encryption Scheme 2 / Key Derivation Function 2 (PKCS #5 / RFC 8018) |
| **PCFG** | Probabilistic Context-Free Grammar |
| **PEM** | Privacy-Enhanced Mail (the Base64 key/cert armor) |
| **PKCS** | Public-Key Cryptography Standards (#5 PBE, #7 padding, #8 keys, #12 key stores) |
| **PRF** | Pseudo-Random Function |
| **RAR** | Roshal Archive |
| **RFC** | Request For Comments (IETF standard) |
| **ROCm** | Radeon Open Compute (AMD) |
| **S2K** | String-to-Key (OpenPGP) |
| **SEIPD** | Symmetrically-Encrypted Integrity-Protected Data (OpenPGP packet) |
| **TLA** | Three-Letter Acronym (such as this one) |
| **TMTO** | Time-Memory Trade-Off |
| **TPM** | Trusted Platform Module (BitLocker key protector) |
| **UDF** | Universal Disk Format (optical-disc image) |
| **UTF-16LE / -BE** | 16-bit Unicode Transformation Format, Little-/Big-Endian |
| **VBA** | Visual Basic for Applications (Office macros) |
| **VHD(X)** | Virtual Hard Disk (Microsoft disk image) |
| **WDE** | Whole-Disk Encryption |
| **XTS** | XEX-based Tweaked-codebook mode with ciphertext Stealing (disk-sector mode) |

---

See also: [`CRACKING.md`](CRACKING.md) · [`FILEFORMATS.md`](FILEFORMATS.md) ·
[`PERFORMANCE.md`](PERFORMANCE.md) · [`REFERENCES.md`](REFERENCES.md) ·
[`FAQ.md`](FAQ.md) · the docs index in [`README.md`](README.md).
