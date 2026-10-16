# iWork test vectors

`pages.iwpv2`, `numbers.iwpv2`, `key.iwpv2` are the `.iwpv2` passphrase-verifier
members extracted from password-protected Apple iWork documents (Pages, Numbers,
Keynote **14.5**) supplied for cross-validation. Each is 104 bytes and contains
only the KDF parameters (salt, iteration count), the AES-CBC IV, and the
encrypted verification blob — no document content. The passphrase for all three
is **`Password`**.

They are used as known-answer vectors: the implemented scheme
(PBKDF2-HMAC-SHA1 → AES-128-CBC → `sha256(plain[:32]) == plain[32:64]`) must
accept `Password` and reject anything else.
