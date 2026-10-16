package age

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// The fixture testdata/hello.age was produced by the real `age` 1.1.1 CLI
// (`age -p`) with this passphrase and plaintext, so decrypting it cross-validates
// the implementation against the reference encoder.
const (
	fixturePass  = "correct horse battery staple"
	fixturePlain = "the quick brown fox jumps over the lazy dog\n"
)

func loadFixture(t *testing.T) *Params {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "hello.age"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

func TestAgeDecryptsCLIFixture(t *testing.T) {
	p := loadFixture(t)

	fileKey, ok, err := FileKey([]byte(fixturePass), p)
	if err != nil || !ok {
		t.Fatalf("FileKey = %v, %v; want ok", ok, err)
	}
	if !VerifyMAC(fileKey, p) {
		t.Fatal("header MAC did not verify with the derived file key")
	}
	plain, err := Decrypt(fileKey, p)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(plain, []byte(fixturePlain)) {
		t.Fatalf("decrypted = %q, want %q", plain, fixturePlain)
	}
}

func TestAgeWrongPassphrase(t *testing.T) {
	p := loadFixture(t)
	if _, ok, err := FileKey([]byte("wrong passphrase"), p); err != nil || ok {
		t.Fatalf("FileKey with wrong passphrase = %v, %v; want not ok", ok, err)
	}
}

func TestAgeParseRejectsNonAge(t *testing.T) {
	if _, err := Parse([]byte("not an age file")); err != ErrNotAge {
		t.Fatalf("Parse(non-age) = %v, want ErrNotAge", err)
	}
}

func TestAgeChallenge(t *testing.T) {
	p := loadFixture(t)
	ch := Challenge(p)
	if ch.Scheme != "age-scrypt" || ch.Cipher.Algo != "chacha20-poly1305" {
		t.Fatalf("unexpected challenge: %+v", ch)
	}
	if len(ch.Extra["wrapped_key"]) != 32 {
		t.Fatalf("wrapped_key length = %d, want 32", len(ch.Extra["wrapped_key"]))
	}
}
