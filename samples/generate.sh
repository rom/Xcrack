#!/usr/bin/env bash
# Regenerate the Xcrack demo/sample files. Each encrypted sample uses the
# passphrase "opensesame" (the ZipCrypto known-plaintext demo uses "sesame"),
# both of which live in wordlist.txt so `xcrack -w samples/wordlist.txt <file>`
# cracks every sample. Run from anywhere:  bash samples/generate.sh
#
# Requires: zip, 7z, openssl, gpg, ssh-keygen, keytool, puttygen, sqlcipher,
#           qpdf (optional), rar (optional), plus `go` for the PDF and the
#           ZipCrypto known-plaintext artifacts. Tools that are absent are
#           skipped with a note; the committed samples are the canonical copy.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
PASS="opensesame"
cd "$HERE"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ok()   { printf '  ok   %s\n' "$1"; }
skip() { printf '  SKIP %s (%s)\n' "$1" "$2"; }
have() { command -v "$1" >/dev/null 2>&1; }

# The shared cleartext payload every container sample wraps.
printf 'Xcrack demo payload.\nThe quick brown fox jumps over the lazy dog. 0123456789.\n' > "$tmp/payload.txt"

echo "generating samples in $HERE"

# --- ZIP (traditional ZipCrypto) ---
if have zip; then
  rm -f zipcrypto.zip
  (cd "$tmp" && zip -q --password "$PASS" out.zip payload.txt) && mv "$tmp/out.zip" zipcrypto.zip && ok zipcrypto.zip || skip zipcrypto.zip "zip failed"
else skip zipcrypto.zip "zip not installed"; fi

# --- ZIP (WinZip AES-256) ---
if have 7z; then
  rm -f winzip-aes.zip
  7z a -tzip -p"$PASS" -mem=AES256 -bso0 -bsp0 "$tmp/waes.zip" "$tmp/payload.txt" >/dev/null 2>&1 \
    && mv "$tmp/waes.zip" winzip-aes.zip && ok winzip-aes.zip || skip winzip-aes.zip "7z failed"
else skip winzip-aes.zip "7z not installed"; fi

# --- 7z (header-encrypted: names hidden too) ---
if have 7z; then
  rm -f secret.7z
  7z a -p"$PASS" -mhe=on -bso0 -bsp0 "$tmp/s.7z" "$tmp/payload.txt" >/dev/null 2>&1 \
    && mv "$tmp/s.7z" secret.7z && ok secret.7z || skip secret.7z "7z failed"
else skip secret.7z "7z not installed"; fi

# --- RAR (header-encrypted) ---
if have rar; then
  rm -f secret.rar
  (cd "$tmp" && rar a -idq -hp"$PASS" s.rar payload.txt) >/dev/null 2>&1 \
    && mv "$tmp/s.rar" secret.rar && ok secret.rar || skip secret.rar "rar failed"
else skip secret.rar "rar not installed (non-free)"; fi

# --- Nested: an encrypted zip inside an encrypted zip (demos recursion) ---
if have zip && [ -f zipcrypto.zip ]; then
  rm -f nested.zip
  cp zipcrypto.zip "$tmp/inner.zip"
  (cd "$tmp" && zip -q --password "$PASS" outer.zip inner.zip) && mv "$tmp/outer.zip" nested.zip && ok nested.zip || skip nested.zip "zip failed"
else skip nested.zip "need zip + zipcrypto.zip"; fi

# --- PDF (AES-256 / AESV3), built by the in-tree generator ---
rm -f secret.pdf
if (cd "$ROOT/xfileformats" && go run "$HERE/pdfgen.go" "$HERE/secret.pdf" "$PASS") >/dev/null 2>&1; then
  ok secret.pdf
else skip secret.pdf "go/pdfgen failed"; fi

# --- age (scrypt passphrase) ---
if have age; then
  rm -f secret.age
  if python3 ptyage.py "$PASS" secret.age "$tmp/payload.txt" >/dev/null 2>&1; then ok secret.age; else skip secret.age "age pty driver failed"; fi
else skip secret.age "age not installed"; fi

# --- OpenPGP symmetric (gpg -c) ---
if have gpg; then
  rm -f secret.gpg
  gpg --batch --yes --pinentry-mode loopback --passphrase "$PASS" --s2k-mode 3 \
      --cipher-algo AES256 -o secret.gpg -c "$tmp/payload.txt" >/dev/null 2>&1 \
    && ok secret.gpg || skip secret.gpg "gpg failed"
else skip secret.gpg "gpg not installed"; fi

# --- OpenSSH private key (bcrypt-pbkdf + aes-ctr) ---
if have ssh-keygen; then
  rm -f id_ed25519 id_ed25519.pub
  ssh-keygen -q -t ed25519 -N "$PASS" -C xcrack-demo -f id_ed25519 >/dev/null 2>&1 \
    && rm -f id_ed25519.pub && ok id_ed25519 || skip id_ed25519 "ssh-keygen failed"
else skip id_ed25519 "ssh-keygen not installed"; fi

# --- Encrypted private keys (PKCS#8 PBES2 and traditional DEK-Info) ---
if have openssl; then
  rm -f privkey_pkcs8.pem privkey_traditional.pem
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -aes256 -pass pass:"$PASS" -out privkey_pkcs8.pem >/dev/null 2>&1 \
    && ok privkey_pkcs8.pem || skip privkey_pkcs8.pem "openssl failed"
  openssl genrsa -aes256 -traditional -passout pass:"$PASS" 2048 >privkey_traditional.pem 2>/dev/null \
    && [ -s privkey_traditional.pem ] && ok privkey_traditional.pem || { skip privkey_traditional.pem "openssl genrsa -traditional failed"; rm -f privkey_traditional.pem; }
else skip privkey_pkcs8.pem "openssl not installed"; fi

# --- PKCS#12 (.p12) ---
if have openssl; then
  rm -f keystore.p12
  openssl req -x509 -newkey rsa:2048 -keyout "$tmp/k.pem" -out "$tmp/c.pem" -days 1 -nodes -subj /CN=xcrack-demo >/dev/null 2>&1 \
    && openssl pkcs12 -export -inkey "$tmp/k.pem" -in "$tmp/c.pem" -name demo -passout pass:"$PASS" -out keystore.p12 >/dev/null 2>&1 \
    && ok keystore.p12 || skip keystore.p12 "openssl pkcs12 failed"
else skip keystore.p12 "openssl not installed"; fi

# --- JKS (Java KeyStore) ---
if have keytool; then
  rm -f keystore.jks
  keytool -genkeypair -keystore keystore.jks -storetype JKS -storepass "$PASS" -keypass "$PASS" \
    -alias demo -dname CN=xcrack-demo -keyalg RSA -keysize 2048 -validity 1 >/dev/null 2>&1 \
    && ok keystore.jks || skip keystore.jks "keytool failed"
else skip keystore.jks "keytool not installed"; fi

# --- PuTTY private key (.ppk v3, Argon2id) ---
if have puttygen; then
  rm -f key.ppk
  printf '%s' "$PASS" > "$tmp/pw.txt"
  puttygen -t ed25519 -C xcrack-demo --new-passphrase "$tmp/pw.txt" -o key.ppk >/dev/null 2>&1 \
    && [ -s key.ppk ] && ok key.ppk || skip key.ppk "puttygen failed"
else skip key.ppk "puttygen not installed"; fi

# --- SQLCipher database (v4 defaults) ---
if have sqlcipher; then
  rm -f notes.db
  sqlcipher "$tmp/notes.db" "PRAGMA key='$PASS'; CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT); INSERT INTO notes(body) VALUES('xcrack demo row'); " >/dev/null 2>&1 \
    && mv "$tmp/notes.db" notes.db && ok notes.db || skip notes.db "sqlcipher failed"
else skip notes.db "sqlcipher not installed"; fi

# --- ZipCrypto known-plaintext demo (for `xcrack kp`) ---
rm -f kp_entry.bin kp_cipher.bin kp_known.txt
if (cd "$ROOT/xcrypto" && go run "$HERE/kpgen.go" "$HERE") >/dev/null 2>&1; then
  ok "kp_entry.bin / kp_cipher.bin / kp_known.txt"
else skip "kp_* (known-plaintext demo)" "go/kpgen failed"; fi

echo "done."
echo
echo "Formats that need a real Office install (not generatable here) are omitted:"
echo "  legacy MS Office (.doc/.xls/.ppt), encrypted OOXML (.docx), and ODF with a"
echo "  password. Example fixtures for those live under the per-package testdata/"
echo "  directories (e.g. xfileformats/formats/msoffice/testdata)."
