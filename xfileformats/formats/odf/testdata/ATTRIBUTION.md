# ODF test fixtures

- `libreoffice-aes256cbc.odt` — an empty-ish ODF text document created and
  password-protected with **LibreOffice 24.2.7.2** (`soffice`), passphrase
  **`opensesame`**. LibreOffice 24.2 encrypts ODF packages with AES-256-CBC
  (PBKDF2-HMAC-SHA1, 100000 iterations, SHA-256 start key, sha256-1k checksum).
  Used to cross-validate the ODF CBC decryption path against a real producer,
  rather than only against this repo's own fixture encryptor.

  Regenerate with `scripts`-style tooling: create any document in LibreOffice,
  Save As with "Save with password".
