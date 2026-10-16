# Xcrack sample files

A small, self-contained set of encrypted sample files for demos, manual
testing, and development. **Every passphrase-protected file here uses the
passphrase `opensesame`** (the ZipCrypto known-plaintext demo uses `sesame`).
Both live in [`wordlist.txt`](wordlist.txt), so a single command cracks any of
them:

```sh
make build                              # or: (cd xcrack && go build -o ../bin/xcrack ./cmd/xcrack)
./bin/xcrack -w samples/wordlist.txt samples/zipcrypto.zip
./bin/xcrack -w samples/wordlist.txt samples/secret.pdf
./bin/xcrack -w samples/wordlist.txt samples/*.zip samples/*.pem samples/key.ppk
```

`xcrack identify samples/<file>` reports the detected format without cracking.

> These are deliberately trivial passwords on throwaway keys/data — for
> demonstrating recovery only. Nothing here is a real secret.

## Manifest

| File | Format | Password | How it was made |
|------|--------|----------|-----------------|
| `zipcrypto.zip` | ZIP, traditional **ZipCrypto** | `opensesame` | `zip --password` |
| `winzip-aes.zip` | ZIP, **WinZip AES-256** | `opensesame` | `7z -tzip -mem=AES256` |
| `secret.7z` | **7z**, header-encrypted (`-mhe`) | `opensesame` | `7z -mhe=on` |
| `secret.rar` | **RAR**, header-encrypted (`-hp`) | `opensesame` | `rar a -hp` |
| `nested.zip` | ZipCrypto zip **containing** `zipcrypto.zip` | `opensesame` | demos recursion (both layers) |
| `secret.pdf` | **PDF**, AES-256 (AESV3) | `opensesame` | in-tree `pdfgen.go` |
| `secret.age` | **age**, scrypt passphrase | `opensesame` | `age -p` |
| `secret.gpg` | **OpenPGP** symmetric (`gpg -c`) | `opensesame` | `gpg -c --cipher-algo AES256` |
| `id_ed25519` | **OpenSSH** private key | `opensesame` | `ssh-keygen -t ed25519 -N` |
| `privkey_pkcs8.pem` | **PKCS#8** PBES2 (PBKDF2+AES) | `opensesame` | `openssl genpkey -aes256` |
| `privkey_traditional.pem` | **PEM** traditional (DEK-Info) | `opensesame` | `openssl genrsa -aes256 -traditional` |
| `keystore.p12` | **PKCS#12** (.p12/.pfx) | `opensesame` | `openssl pkcs12 -export` |
| `keystore.jks` | **JKS** Java KeyStore | `opensesame` | `keytool -genkeypair` |
| `key.ppk` | **PuTTY** `.ppk` v3 (Argon2id) | `opensesame` | `puttygen -t ed25519 --new-passphrase` |
| `notes.db` | **SQLCipher** v4 database | `opensesame` | `sqlcipher "PRAGMA key=…"` |
| `kp_entry.bin`, `kp_cipher.bin`, `kp_known.txt` | **ZipCrypto known-plaintext** demo | `sesame` | in-tree `kpgen.go` |

## Notes

- **SQLCipher (`notes.db`)** has no cleartext magic, so `xcrack identify` reports
  "unknown format" and the engine does not auto-detect it. Use the library
  (`xcrypto/scheme/sqlcipher`) directly, targeting the file explicitly.
- **Known-plaintext demo (`kp_*`)** is for the `xcrack kp` subcommand, which
  recovers the ZipCrypto key without a password. `kp_known.txt` is the known
  payload, `kp_cipher.bin` the matching ciphertext, `kp_entry.bin` the full
  entry (12-byte header + data):

  ```sh
  # fast path: offload the search to a local bkcrack binary, then recover all
  ./bin/xcrack kp --plain samples/kp_known.txt --cipher samples/kp_cipher.bin \
      --bkcrack /path/to/bkcrack \
      --decrypt samples/kp_entry.bin --offset 0 --recover-password 6:?l
  ```

  Without `--bkcrack` the attack runs in-process (correct, but compute-heavy —
  minutes to an hour; see `docs/USAGE.md`).
- **Legacy MS Office (`.doc/.xls/.ppt`), encrypted OOXML (`.docx`), and
  password-protected ODF** are not included: they require a real Office/Office-
  compatible writer to produce and are not generatable from the CLI tools here.
  Example fixtures for those formats live under the per-package `testdata/`
  directories (e.g. `xfileformats/formats/msoffice/testdata`).

## Regenerating

```sh
bash samples/generate.sh      # or: make samples
```

The script uses `zip`, `7z`, `openssl`, `gpg`, `ssh-keygen`, `keytool`,
`puttygen`, `sqlcipher`, optionally `rar`, and `go` (for the PDF and
known-plaintext artifacts via `pdfgen.go` / `kpgen.go`; `ptyage.py` drives
`age`'s terminal-only passphrase prompt). Any missing tool is skipped with a
note — the committed files are the canonical copy.
