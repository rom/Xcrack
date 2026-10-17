# Xcrack — Terminology & Glossary

A reference for the vocabulary used across the Xcrack docs and code: the engine's
own concepts, the cryptographic primitives and ciphers it works against, the file
formats and containers it understands, the attacks and shortcuts it brings to
bear, and the abbreviations and three-letter acronyms (TLAs) that recur
throughout.

It is a companion to the three reference documents — [`CRACKING.md`](CRACKING.md)
(how each format is attacked), [`FILEFORMATS.md`](FILEFORMATS.md) (what is
detected and parsed), and [`REFERENCES.md`](REFERENCES.md) (primary sources). When
a term is explained in depth elsewhere, the entry points there.

> Authorized use only. Xcrack is a recovery/defensive tool: operate on files you
> own or are explicitly permitted to access.

---

## 1. Engine, recursion & result model

The core vocabulary of Xcrack's recursive-decomposition engine (see
[`design.md`](design.md) and [ADR 0003](adr/0003-recursive-decomposition-model.md)).

| Term | Meaning |
| ---- | ------- |
| **Candidate** | A single password string to test against a file. |
| **Challenge** | The crypto material (salt, verifier, KDF parameters) a format exposes so candidates can be tested without re-reading the whole file. The portable form is the **challenge envelope** (a JSON blob exported with `xcrack export-challenge` and consumed by an external cracker or `--resume-from`). |
| **Encryption layer** | A file (or entry) that is password-protected and must be decrypted. |
| **Container layer** | A file (or entry) that holds other files (an archive or compound document) and must be unpacked. |
| **Node** | One position in the decomposition tree — a file at some depth, with its format, the password that unlocked it (if any), its content, and its children. |
| **Leaf** | A node that is neither encrypted nor a container: real content handed back to the caller. |
| **Password promotion** | Trying a password that unlocked an outer layer first on inner layers, since nested packaging reuses passwords. Corpus-wide promotion across unrelated files is `--adaptive`. |
| **Budget / limits** | The caps (depth, total bytes, node count, compression ratio, time) that bound work and defeat decompression bombs (see [ADR 0004](adr/0004-hostile-input-safety-budgets.md)). |
| **Format** | A plugin that recognizes one file type. May be `Encrypted` (has a KDF/verifier), a `Container` (unpacks to entries), `Explodable` (a document that can be decomposed into parts), or several at once. |
| **Registry** | The explicit set of registered formats the engine consults; `DetectAll` ranks every format's confidence against a file's leading bytes and picks the best. |
| **Detection** | Choosing a format by **content** (magic bytes / structure), not by file extension — so an encrypted file inside an archive is handled correctly however its entry is named. |
| **Probe** | The one-time step that reads a file's salt, iteration count and verifier into a `Challenge`, done once per file before any candidate is tried. |
| **Verifier** | The cheap pass/fail check that distinguishes a wrong password from a right one without decrypting the whole body (e.g. a 2-byte value, an HMAC, a padding check). |
| **Fast-reject** | An even cheaper 1–2 byte check tried *before* the KDF runs, to discard most wrong guesses; the authoritative verifier is always re-run on anything it passes, so it can never cause a false positive. |
| **Decompose / decomposition** | Unpacking a container (or exploding a document) into child entries the engine then re-detects and recurses into. |
| **Document explosion** | The opt-in `--explode-documents` mode that decomposes an Office document (OOXML/OLE) into its internal parts so the engine recurses into each, instead of treating the document as an opaque leaf ([ADR 0007](adr/0007-documents-as-leaves.md)). |
| **Potfile / found-password cache** | A persistent file of recovered passwords (`--found-cache` / `--remember`, hashcat-style "pot") whose entries lead the candidate stream so a reused password is recovered instantly next run. |
| **Loopback** | Re-feeding already-recovered passwords back through the rule engine as fresh candidates (`--loopback`), a hashcat idiom. |
| **Shard** | A disjoint `I/N` stride of the keyspace handed to one worker (`--shard I/N`) so a search can be split across processes or machines. |
| **Cluster** | A fleet of `xcrackd` workers that xcrack fans a search out to — *collective* (many servers, one file) or *partition* (server groups on different files). |
| **Manifest** | The `manifest.json` written alongside an extracted tree: the per-node format, password, and content hashes. |

## 2. Key derivation & hashing

How a password becomes a key, and the hashing that underlies it. See
[`REFERENCES.md`](REFERENCES.md) §1 for the standards.

| Term | Meaning |
| ---- | ------- |
| **KDF** (Key Derivation Function) | The function that turns a password (+ salt + parameters) into a cryptographic key. Deliberately slow KDFs are the main obstacle to a password search. |
| **PBKDF2** | Password-Based KDF 2 (RFC 8018): HMAC iterated a set number of times. Xcrack meets it with HMAC-SHA1/-SHA256/-SHA512; it is the GPU tier's primary accelerated step. |
| **HMAC** | Hash-based Message Authentication Code (RFC 2104): a keyed hash construction, the PRF inside PBKDF2 and a common verifier. |
| **PRF** (Pseudo-Random Function) | The keyed function a KDF iterates (for PBKDF2, an HMAC); the engine's `AccelKDF` carries a PRF selector so the right GPU kernel is chosen. |
| **Argon2** (d / i / id) | The memory-hard, Password-Hashing-Competition-winning KDF (KeePass KDBX4, PuTTY v3). Memory-hardness makes it GPU-hostile — Xcrack keeps it on the CPU. |
| **scrypt** | A memory-hard KDF (age, Ethereum keystore, some PBES2). Like Argon2, deliberately CPU-bound for a cracker. |
| **bcrypt / bcrypt-pbkdf** | A Blowfish-based password hash; `bcrypt-pbkdf` keys OpenSSH private keys. GPU-hostile. |
| **AES-KDF** | KeePass's iterated AES-256-ECB key-stretch (KDBX3.1, optional in KDBX4); GPU-accelerable because the seed is shared across candidates. |
| **S2K** (String-to-Key) | OpenPGP's password-to-key conversion (iterated-salted mode for `gpg -c`); a cheap iterated hash. |
| **Salt** | Random per-file (or per-entry) bytes mixed into the KDF so the same password yields different keys and precomputed tables don't apply. A KDF missing a salt (see PDF R5, §5) is much weaker. |
| **Spin / iteration count** | The number of KDF repetitions (e.g. Office agile's ~100 000 iterated-hash **spin**, PBKDF2's iteration count); always *read from the file*, never assumed. |
| **DK / dkLen** | Derived Key and its length in bytes — PBKDF2's output and requested size. |
| **Start key / pre-hash** | A format-specific hash applied to the password *before* the main KDF (ODF's SHA-256/SHA-1 start key); carried per-candidate on the CPU via `AccelKDF.PreHash` when the main spin is offloaded. |
| **UTF-16LE** | The little-endian UTF-16 encoding many Microsoft formats hash the password in (e.g. `MD5(UTF16LE(pw))`). |
| **MD5 / SHA-1 / SHA-256 / SHA-512** | Message-digest / Secure-Hash-Algorithm hash functions used as KDF/verifier building blocks across the formats. |
| **Keccak-256** | The hash (SHA-3 family, pre-standard padding) used in the Ethereum keystore MAC. |

## 3. Ciphers, modes & authentication

The bulk ciphers and the modes/MACs wrapped around them.

| Term | Meaning |
| ---- | ------- |
| **AES** | Advanced Encryption Standard, the dominant block cipher (128/192/256-bit keys) across modern formats. |
| **RC4** | A legacy stream cipher (legacy Office, PDF RC4 revisions). Weak, and the lever for the 40-bit key attacks. |
| **ChaCha20-Poly1305** | The AEAD stream cipher + MAC used by `age`. |
| **Blowfish / 3DES** | Legacy block ciphers (Blowfish underlies bcrypt; 3DES unwraps the DMG v1 key). |
| **ZipCrypto / PKWARE** | The traditional ZIP stream cipher (bespoke 3×32-bit key schedule): cryptographically broken (see §5). |
| **CBC** (Cipher Block Chaining) | A block-cipher mode where each block is XORed with the previous ciphertext; needs an IV and padding. |
| **CTR** (Counter) | A mode that turns a block cipher into a stream cipher by encrypting a counter (WinZip-AES, PDF AESV3). |
| **ECB** (Electronic Codebook) | The mode-less block mode (each block independent); used inside OOXML standard and the AES-KDF stretch, not for bulk data. |
| **GCM** (Galois/Counter Mode) | An AEAD mode: CTR encryption plus an authentication tag (ODF 1.3's authenticated variant). |
| **CFB** (Cipher Feedback) | A self-synchronizing stream mode (OpenPGP's SEIPD packet). *Not to be confused with CFB the compound-file container — see §4.* |
| **XTS** | A block-cipher mode for disk sectors (full-volume encryption — out of scope for now). |
| **AEAD** | Authenticated Encryption with Associated Data: encryption that also authenticates, so a wrong key fails the tag (GCM, ChaCha20-Poly1305). |
| **MAC** | Message Authentication Code — a keyed integrity tag (HMAC, the PKCS#12 MacData, the Ethereum Keccak MAC); often doubles as the verifier. |
| **MDC** (Modification Detection Code) | OpenPGP's SHA-1 integrity trailer inside a SEIPD packet, used as a second verifier after the 2-byte CFB quick-check. |
| **IV / nonce** | Initialization Vector / number-used-once — the non-secret per-message value a mode needs; reuse under one key is what breaks ZipCrypto cross-entry and the Office keystream-reuse weakness. |
| **Key schedule** | The expansion of a key into per-round (or per-block) subkeys; ZipCrypto's three 32-bit keys are its (invertible) schedule. |

## 4. File formats, containers & key stores

The on-disk structures Xcrack recognizes. The full catalogue with detection and
cross-validation is in [`FILEFORMATS.md`](FILEFORMATS.md).

| Term | Meaning |
| ---- | ------- |
| **Magic** | The fixed leading bytes that identify a format (e.g. `PK\x03\x04` for ZIP, `28 B5 2F FD` for zstd). |
| **OOXML** (Office Open XML) | The modern `.docx/.xlsx/.pptx` family — a ZIP of XML parts; encrypted ones are an OLE/CFB wrapper around the ZIP. |
| **OLE2 / CFB** (Compound File Binary) | Microsoft's "compound file" container (a FAT-like filesystem in a file) holding legacy `.doc/.xls/.ppt` streams and the encrypted-OOXML package. *CFB here is the container, distinct from CFB the cipher mode in §3.* |
| **VBA** | Visual Basic for Applications — Office macro streams; their auxiliary encryption is staged, not shipped. |
| **ZipCrypto** | ZIP's legacy encryption (see §3/§5). |
| **WinZip-AES** (AE-1 / AE-2) | ZIP's AES extension (extra field `0x9901`): PBKDF2-HMAC-SHA1 ×1000 + AES-CTR + HMAC-SHA1. **AE-2** omits the CRC that **AE-1** keeps (the AE-1 CRC leak is a plaintext-only weakness, §5). |
| **ODF** (OpenDocument Format) | LibreOffice/OpenOffice `.odt/.ods/.odp`: a ZIP with PBKDF2-HMAC-SHA1 + AES-256-CBC (or authenticated -GCM in 1.3). |
| **iWork** | Apple Pages/Numbers/Keynote — a ZIP whose `.iwpv2` verifier is PBKDF2 → AES-128; carries an embedded password **hint** (`.iwph`). |
| **PDF** | Portable Document Format; its encryption **revisions** R2–R6 span 40-bit RC4 to AES-256 (see §5 and [`CRACKING.md`](CRACKING.md)). |
| **DMG** | Apple disk image; the encrypted `encrcdsa` v1/v2 forms use PBKDF2-HMAC-SHA1 to unwrap an AES-128/256 key. |
| **Jet / ACE** | Microsoft Access database engines — **Jet** (`.mdb`, Access 97–2003) stores the password XOR-obfuscated (recoverable with no cracking); **ACE** (`.accdb`, 2007+) uses a real Office-style KDF. |
| **KDBX** | The KeePass database format — **KDBX3.1** (AES-KDF) and **KDBX4** (Argon2d/id or AES-KDF). |
| **JKS** | Java KeyStore — a SHA-1 integrity digest over the password + a fixed phrase + the store body. |
| **PKCS#12** (`.p12`/`.pfx`) | The RFC 7292 key-store format; verified by its MacData HMAC independently of bag encryption. |
| **PKCS#8 / PEM** | Private-key encodings; PEM is the Base64 "`-----BEGIN…`" armor, PKCS#8 the key structure (PBES2 = PBKDF2/scrypt, or legacy `EVP_BytesToKey`). |
| **PPK** | PuTTY Private Key file — Argon2 (v3) or SHA-1 (v2) with a Private-MAC verifier. |
| **SQLCipher** | Encrypted SQLite — PBKDF2-HMAC-SHA512 ×256k (v4) or -SHA1 ×64k (v3), page-1 HMAC verifier. |
| **MIME / `.eml`** | The email container; its Base64/quoted-printable attachments are decoded and handed to their own formats. |
| **SEIPD** | OpenPGP's Symmetrically-Encrypted-Integrity-Protected-Data packet (`gpg -c` output, CFB + MDC). |
| **Skippable frame** | A zstd frame (magic `50..5F 2A 4D 18`) carrying out-of-band metadata that a decoder passes over — detected so a zstd stream that leads with one is still recognized. |

## 5. Attacks, cryptanalysis & shortcuts

What is tried, and the structural weaknesses Xcrack exploits (or documents). The
authoritative, per-format treatment is [`CRACKING.md`](CRACKING.md) §3.

| Term | Meaning |
| ---- | ------- |
| **Brute force** | Exhaustively trying a keyspace (all strings of a length/charset). The fallback when no better candidate order exists. |
| **Dictionary / wordlist attack** | Trying entries from a list of likely passwords, optionally rule-mangled — almost always the highest-yield attack. |
| **Mask** | A per-position charset template (hashcat `?l?u?d?s`) describing a structured keyspace. |
| **Rule** | A per-word transform (append, capitalize, leet-substitute, …) in the hashcat rule language; Xcrack implements the full function + reject set. |
| **Hybrid** | A wordlist with a mask appended or prepended (hashcat `-a 6/7`). |
| **Combinator** | Concatenating two wordlists (hashcat `-a 1`). |
| **PRINCE** | PRobability INfinite Chained Elements — Jens Steube's chained-word generator. |
| **PCFG** | Probabilistic Context-Free Grammar — Weir et al.'s structure-learned candidate generation (`--pcfg`). |
| **Markov** | Letter-transition-probability ordering/generation (Narayanan–Shmatikov), so likelier strings are tried first (`--order markov`, `--markov`). |
| **Spray / breach corpus** | Trying a few very common passwords across many targets (spray), or a frequency-ordered leaked-password list (breach). |
| **KPA** (Known-Plaintext Attack) | Recovering key material from known plaintext rather than the password. For ZipCrypto, ~12 known plaintext bytes recover the internal key state. |
| **Biham–Kocher** | The 1994 known-plaintext attack on ZipCrypto's stream cipher; recovers the 96-bit internal state with no password. Implemented in-tree (`xcrack kp`) with an optional **bkcrack** offload. |
| **Cross-entry key reuse** | Because every ZipCrypto entry shares one password-derived key state, one recovery decrypts the whole archive with no further search. |
| **Reduced known-plaintext** (Stay 2001) | Michael Stay's reduction of the ZipCrypto KPA to as little as 2–3 known bytes in many cases — documented, not built (the recovered keys, not the password, are what Xcrack needs, and ~12 bytes of compressed plaintext is nearly always available). |
| **Weak-RNG "guaranteed recovery"** (Stay 2001) | Legacy WinZip ≤8.0 / NetZip generated the 12-byte encryption header with MSVC `rand()` (a 31-bit seed), so the key state is recoverable with **no** known plaintext when an archive has ≥5 encrypted entries — documented as staged (niche legacy archivers, no obtainable oracle fixture). |
| **Key attack** | Sweeping the *key* space directly when the password collapses to a short key — the 40-bit RC4 attacks on Office 97/2000 (`office-keyattack`) and PDF V1/R2 (`pdf-keyattack`). |
| **TMTO / Thunder Tables** | Time-Memory Trade-Off (Hellman 1980; Oechslin rainbow tables 2003); Elcomsoft's precomputed-table product name for the instant 40-bit PDF key recovery. |
| **Keystream reuse / two-time pad** | Encrypting two messages with the same keystream (same key+IV) lets their XOR cancel the keystream and leak plaintext (the Office RC4 re-save weakness, Wu 2005) — recovers plaintext, not the password. |
| **Verification shortcut** | Any way to test or recover a key more cheaply than running the full KDF per candidate (a fast verifier, a header check value, a key attack, or a no-crack decode like the Access Jet header). |
| **VelvetSweatshop / empty password** | Fixed/empty keys that unlock documents with zero real search — Excel's read-only `VelvetSweatshop`, and the empty **user** password that opens owner-restricted PDFs of every revision. |
| **KAT** (Known-Answer Test) | A fixed input→output vector used to cross-validate a scheme against an external oracle. |
| **Oracle** | The independent, trusted implementation (a real CLI, a published vector) a scheme's output is checked against. |

## 6. Acceleration & operations

| Term | Meaning |
| ---- | ------- |
| **GPU tier** | The opt-in, hardware-gated OpenCL acceleration in `xcrackd` (`-tags opencl`, `--gpu`) that batches the KDF onto a device; never in the pure-Go default or CI ([ADR 0001](adr/0001-pure-go-no-external-binaries.md) amendment). |
| **OpenCL** | The vendor-neutral compute API the GPU kernels are written in; runs on NVIDIA/AMD/Intel/Apple through each vendor's **ICD** (Installable Client Driver). |
| **ROCm / HIP / CUDA** | AMD's (ROCm/HIP) and NVIDIA's (CUDA) native compute stacks — a documented future back-end; the OpenCL kernels already run on those GPUs via the ICD. |
| **pocl** | Portable Computing Language — a CPU OpenCL implementation used to validate the GPU path in CI-less containers. |
| **Hash-line / `*2john`** | A one-line text encoding of a file's crypto parameters (`$office$`, `$pdf$`, `$zip2$`, `$dmg$`) for offloading to **hashcat** / **John the Ripper** (JtR). |
| **Fast mode** | (Claude Code) an output-speed option, unrelated to Xcrack cracking. |

## 7. Abbreviations & TLAs

A quick-reference index of the acronyms used across the docs (expanded in context
above).

| Abbrev. | Expansion |
| ------- | --------- |
| **ADR** | Architecture Decision Record |
| **AEAD** | Authenticated Encryption with Associated Data |
| **AES** | Advanced Encryption Standard |
| **API** | Application Programming Interface |
| **ASR** | Architecturally Significant Requirement |
| **CBC / CTR / ECB / GCM / CFB / XTS** | block-cipher modes (§3) |
| **CFB** | Cipher Feedback (mode) **or** Compound File Binary (container) — disambiguate by context |
| **CLI** | Command-Line Interface |
| **CRC** | Cyclic Redundancy Check (CRC32 is ZipCrypto's content verifier) |
| **CSPRNG / RNG** | (Cryptographically-Secure) Random Number Generator |
| **CTF** | Capture The Flag (security competition) |
| **DFIR** | Digital Forensics & Incident Response |
| **DK** | Derived Key |
| **DMCA** | Digital Millennium Copyright Act (the law behind the Sklyarov case) |
| **DRM** | Digital Rights Management |
| **HMAC** | Hash-based Message Authentication Code |
| **ICD** | Installable Client Driver (OpenCL) |
| **IV** | Initialization Vector |
| **JtR** | John the Ripper (password cracker) |
| **KAT** | Known-Answer Test |
| **KDF** | Key Derivation Function |
| **KPA** | Known-Plaintext Attack |
| **MAC** | Message Authentication Code |
| **MDC** | Modification Detection Code (OpenPGP) |
| **MITM** | Man-In-The-Middle |
| **MVP** | Minimum Viable Product |
| **OLE** | Object Linking & Embedding (OLE2 = the compound-file container) |
| **OOXML** | Office Open XML |
| **PBES2 / PBKDF2** | Password-Based Encryption Scheme 2 / Key Derivation Function 2 (PKCS #5 / RFC 8018) |
| **PCFG** | Probabilistic Context-Free Grammar |
| **PEM** | Privacy-Enhanced Mail (the Base64 key/cert armor) |
| **PKCS** | Public-Key Cryptography Standards (#5 PBE, #7 padding, #8 keys, #12 key stores) |
| **PRF** | Pseudo-Random Function |
| **RFC** | Request For Comments (IETF standard) |
| **S2K** | String-to-Key (OpenPGP) |
| **SEIPD** | Symmetrically-Encrypted Integrity-Protected Data (OpenPGP packet) |
| **TLA** | Three-Letter Acronym (such as this one) |
| **TMTO** | Time-Memory Trade-Off |
| **UTF-16LE** | 16-bit Unicode Transformation Format, Little-Endian |
| **VBA** | Visual Basic for Applications (Office macros) |

---

See also: [`CRACKING.md`](CRACKING.md) · [`FILEFORMATS.md`](FILEFORMATS.md) ·
[`REFERENCES.md`](REFERENCES.md) · [`FAQ.md`](FAQ.md) · the docs index in
[`README.md`](README.md).
