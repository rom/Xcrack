package pgp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// testdata/hello.gpg was produced by the real GnuPG 2.4 CLI
// (gpg --rfc4880 -c --cipher-algo AES256 --s2k-digest-algo SHA256) with this
// passphrase and plaintext, cross-validating the implementation.
const (
	fixturePass  = "correct horse battery staple"
	fixturePlain = "the quick brown fox jumps over the lazy dog\n"
)

func loadFixture(t *testing.T) *Message {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "hello.gpg"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	m, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

func TestPGPDecryptsCLIFixture(t *testing.T) {
	m := loadFixture(t)
	if m.CipherAlgo != cipherAES3 || m.S2KType != 3 {
		t.Fatalf("unexpected params: cipher=%d s2k=%d", m.CipherAlgo, m.S2KType)
	}
	ok, err := Verify([]byte(fixturePass), m)
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want ok", ok, err)
	}
	plain, err := Decrypt([]byte(fixturePass), m)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain, []byte(fixturePlain)) {
		t.Fatalf("decrypted = %q, want %q", plain, fixturePlain)
	}
}

func TestPGPWrongPassphrase(t *testing.T) {
	m := loadFixture(t)
	if ok, err := Verify([]byte("wrong passphrase"), m); err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false", ok, err)
	}
}

func TestPGPParseRejectsNonPGP(t *testing.T) {
	if _, err := Parse([]byte("not a pgp message at all, just text")); err == nil {
		t.Fatal("expected an error for non-PGP input")
	}
}

func TestPGPDecryptsArmoredFixture(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "hello.asc"))
	if err != nil {
		t.Skipf("armored fixture unavailable: %v", err)
	}
	m, err := Parse(data) // Parse de-armors transparently
	if err != nil {
		t.Fatalf("Parse(armored): %v", err)
	}
	plain, err := Decrypt([]byte(fixturePass), m)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plain, []byte(fixturePlain)) {
		t.Fatalf("armored decrypt = %q, want %q", plain, fixturePlain)
	}
}
