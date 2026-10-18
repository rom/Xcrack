package securecache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// xorSealer is a reversible software sealer for testing the sealed-cache path
// without a TPM: it tags and XORs the DEK with a fixed key. A different key
// (a different instance) cannot recover the DEK, modelling a wrong/foreign TPM.
type xorSealer struct{ key byte }

func (s xorSealer) Name() string { return "xor-test" }
func (s xorSealer) Seal(dek []byte) ([]byte, error) {
	out := append([]byte("X"), dek...)
	for i := 1; i < len(out); i++ {
		out[i] ^= s.key
	}
	return out, nil
}
func (s xorSealer) Unseal(blob []byte) ([]byte, error) {
	if len(blob) < 1 || blob[0] != 'X' {
		return nil, errors.New("bad blob")
	}
	out := append([]byte(nil), blob[1:]...)
	for i := range out {
		out[i] ^= s.key
	}
	return out, nil
}

func TestPlaintextRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "found.txt")
	s, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.Encrypted() {
		t.Error("nil sealer should be plaintext")
	}
	if err := s.Add("alpha", "beta", "alpha"); err != nil { // dup ignored
		t.Fatal(err)
	}
	if err := s.Add("gamma"); err != nil {
		t.Fatal(err)
	}
	// Reopen and confirm persistence + order + dedup.
	s2, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := s2.Passwords()
	want := []string{"alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// The plaintext file is the historical newline format.
	raw, _ := os.ReadFile(path)
	if string(raw) != "alpha\nbeta\ngamma\n" {
		t.Fatalf("plaintext file = %q", raw)
	}
}

func TestSealedRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "found.sealed")
	sealer := xorSealer{key: 0x5a}
	s, err := Open(path, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Encrypted() {
		t.Error("non-nil sealer should be encrypted")
	}
	if err := s.Add("s3cret", "hunter2"); err != nil {
		t.Fatal(err)
	}
	// The file must not contain the plaintext passwords.
	raw, _ := os.ReadFile(path)
	if len(raw) == 0 {
		t.Fatal("sealed file is empty")
	}
	for _, pw := range []string{"s3cret", "hunter2"} {
		if containsSub(raw, []byte(pw)) {
			t.Fatalf("sealed file leaks plaintext %q", pw)
		}
	}
	// Reopen with the same sealer recovers everything.
	s2, err := Open(path, sealer)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if got := s2.Passwords(); len(got) != 2 || got[0] != "s3cret" || got[1] != "hunter2" {
		t.Fatalf("recovered %v", got)
	}
}

func TestSealedWrongKeyRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "found.sealed")
	s, _ := Open(path, xorSealer{key: 0x11})
	if err := s.Add("topsecret"); err != nil {
		t.Fatal(err)
	}
	// A different sealer (a foreign TPM) must not silently start empty.
	if _, err := Open(path, xorSealer{key: 0x22}); !errors.Is(err, ErrBadCache) {
		t.Fatalf("wrong key: err = %v, want ErrBadCache", err)
	}
}

func TestSealedTamperDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "found.sealed")
	sealer := xorSealer{key: 0x33}
	s, _ := Open(path, sealer)
	if err := s.Add("abc"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	raw[len(raw)-1] ^= 0xff // flip a ciphertext bit
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, sealer); !errors.Is(err, ErrBadCache) {
		t.Fatalf("tampered file: err = %v, want ErrBadCache", err)
	}
}

func TestSealedRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "found.sealed")
	if err := os.WriteFile(path, []byte("not a sealed cache"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, xorSealer{key: 1}); !errors.Is(err, ErrBadCache) {
		t.Fatalf("garbage: err = %v, want ErrBadCache", err)
	}
}

func TestMissingFileIsEmpty(t *testing.T) {
	for _, sealer := range []Sealer{nil, xorSealer{key: 7}} {
		s, err := Open(filepath.Join(t.TempDir(), "nope"), sealer)
		if err != nil {
			t.Fatalf("missing file should be empty, got %v", err)
		}
		if len(s.Passwords()) != 0 {
			t.Fatal("missing file should yield an empty store")
		}
	}
}

func TestTPMSealerUnavailableInDefaultBuild(t *testing.T) {
	// The default (no -tags tpm) build must report TPM support unavailable
	// rather than pretending to seal.
	if TPMBuilt {
		t.Skip("built with -tags tpm")
	}
	if _, err := TPMSealer(); !errors.Is(err, ErrTPMUnavailable) {
		t.Fatalf("TPMSealer() err = %v, want ErrTPMUnavailable", err)
	}
}

func containsSub(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
