# DMG test fixtures

`encrcdsa-aes256.dmg` and `encrcdsa-aes128.dmg` are **minimal `encrcdsa` v2
headers carved from genuine macOS-produced encrypted disk images** supplied as
test samples (password: `opensesame`).

They are not full disk images. Each keeps the real cryptographic parameters —
the PBKDF2 salt, the blob-encryption IV, the wrapped AES/HMAC key blob, the
iteration count, the key size — and one real encrypted data chunk, re-laid out
per the `filevault.h` struct layout with `datasize` set so the on-disk parser
selects that single chunk (`cno = 0`). This makes them a few KB each while still
exercising the real `encrcdsa` parse path and the real crypto end to end: the
correct password `opensesame` verifies and a wrong one does not.

The underlying DMG crypto is additionally cross-validated against John the
Ripper's authoritative `dmg` vectors (see
`xcrypto/scheme/dmg/testdata/john_vectors.txt`).
