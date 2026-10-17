# KeePass KDBX test fixtures

All use passphrase **`opensesame`**. Used to cross-validate the passphrase
verifiers against non-Xcrack producers.

## KDBX4 (Argon2d)

Both created with **pykeepass 4.2.0** (an independent KDBX implementation),
KDBX version 4, KDF **Argon2d** (the KeePass default). Cross-validate the
header-HMAC verifier.

- `pykeepass-argon2d.kdbx` — reduced KDF cost (M=1 MiB, I=2, P=1) so the
  known-answer verify test runs fast in CI. Re-opened successfully by pykeepass
  after the cost edit, confirming it is a valid database.
- `pykeepass-argon2d-default.kdbx` — the library default cost (M=64 MiB, I=14,
  P=2); a realistic, heavier fixture (verify ~2 s), exercised by a `-short`-gated
  test.

## KDBX3 (AES-KDF)

- `kdbx3-aeskdf.kdbx` — a legacy **KDBX version 3.1** database (AES-256-CBC,
  AES-KDF, 6000 transform rounds) built with a standalone pycryptodome script
  and cross-validated by **two** independent oracles: **KeePassXC 2.7.6**
  (`keepassxc-cli ls`/`db-info` open it with the passphrase and report
  "KDF: AES (6000 rounds)"; a wrong passphrase is rejected) and **pykeepass
  4.2.0** (re-reads version (3,1), aeskdf, and recovers the entry). Exercises the
  stream-start-bytes verifier.
