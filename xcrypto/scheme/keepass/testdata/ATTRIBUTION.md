# KeePass KDBX4 test fixtures

Both created with **pykeepass 4.2.0** (an independent KDBX implementation),
passphrase **`opensesame`**, KDBX version 4, KDF **Argon2d** (the KeePass
default). Used to cross-validate the header-HMAC passphrase verifier against a
non-Xcrack producer.

- `pykeepass-argon2d.kdbx` — reduced KDF cost (M=1 MiB, I=2, P=1) so the
  known-answer verify test runs fast in CI. Re-opened successfully by pykeepass
  after the cost edit, confirming it is a valid database.
- `pykeepass-argon2d-default.kdbx` — the library default cost (M=64 MiB, I=14,
  P=2); a realistic, heavier fixture (verify ~2 s), exercised by a `-short`-gated
  test.
