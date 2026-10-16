# Encrypted private-key fixtures

Generated locally with OpenSSL (no third-party data), passphrase `Hunter2!`:

- `trad_rsa.pem` — traditional RSA PEM, AES-256-CBC + DEK-Info
- `legacy_ec.pem`  — traditional EC PEM, AES-256-CBC + DEK-Info
- `pkcs8_aes.pem`  — PKCS#8 PBES2, PBKDF2-HMAC-SHA256 + AES-256-CBC
- `pkcs8_scrypt.pem` — PKCS#8 PBES2, scrypt + AES-256-CBC

Disposable test keys; they protect nothing.
