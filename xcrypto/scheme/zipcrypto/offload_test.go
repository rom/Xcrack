package zipcrypto

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeStub writes an executable shell script that emits body on stdout and
// returns its path. Skips on non-POSIX shells.
func writeStub(t *testing.T, name, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub uses /bin/sh")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// kpVector returns an aligned known plaintext/ciphertext pair and the true keys
// as of before plain[0] (i.e. the initial NewKeys state, since Encrypt consumes
// plain[0] first).
func kpVector(pw, text string) (plain, cipher []byte, want Keys) {
	plain = []byte(text)
	cipher = append([]byte(nil), plain...)
	ek := NewKeys([]byte(pw))
	ek.Encrypt(cipher)
	return plain, cipher, NewKeys([]byte(pw))
}

// TestExternalBkcrackOffload drives RecoverKeysWith through a stub that mimics
// bkcrack's output format, then confirms the recovered keys decrypt the data.
func TestExternalBkcrackOffload(t *testing.T) {
	plain, cipher, want := kpVector("hunter2", "the quick brown fox jumps over the lazy dog 0123456789")
	body := fmt.Sprintf("#!/bin/sh\necho '[12:00:00] Keys'\necho '%08x %08x %08x'\n", want.k0, want.k1, want.k2)
	bin := writeStub(t, "bkcrack-stub.sh", body)

	keys, ok, err := RecoverKeysWith(plain, cipher, ExternalBkcrack{Bin: bin})
	if err != nil {
		t.Fatalf("RecoverKeysWith: %v", err)
	}
	if !ok {
		t.Fatal("RecoverKeysWith: not found")
	}
	if keys != want {
		t.Fatalf("recovered %+v, want %+v", keys, want)
	}
	dec := append([]byte(nil), cipher...)
	keys.Decrypt(dec)
	if string(dec) != string(plain) {
		t.Fatalf("decrypt mismatch: %q", dec)
	}
}

// TestExternalBkcrackOneLine accepts the single-line "Keys: X Y Z" shape too.
func TestExternalBkcrackOneLine(t *testing.T) {
	plain, cipher, want := kpVector("S3cr3t!", "the quick brown fox jumps over the lazy dog 0123456789")
	body := fmt.Sprintf("#!/bin/sh\necho 'Keys: %08x %08x %08x'\n", want.k0, want.k1, want.k2)
	bin := writeStub(t, "bkcrack-oneline.sh", body)

	keys, ok, err := RecoverKeysWith(plain, cipher, ExternalBkcrack{Bin: bin})
	if err != nil || !ok {
		t.Fatalf("RecoverKeysWith: ok=%v err=%v", ok, err)
	}
	if keys != want {
		t.Fatalf("recovered %+v, want %+v", keys, want)
	}
}

// TestExternalBkcrackWrongKeysRejected proves the local re-validation blocks a
// false positive: a stub that prints WRONG keys must yield not-found, not a wrong
// "success".
func TestExternalBkcrackWrongKeysRejected(t *testing.T) {
	plain, cipher, want := kpVector("hunter2", "the quick brown fox jumps over the lazy dog 0123456789")
	// Corrupt each word so the triple is syntactically valid but wrong.
	body := fmt.Sprintf("#!/bin/sh\necho 'Keys'\necho '%08x %08x %08x'\n", want.k0^0xff, want.k1, want.k2)
	bin := writeStub(t, "bkcrack-wrong.sh", body)

	keys, ok, err := RecoverKeysWith(plain, cipher, ExternalBkcrack{Bin: bin})
	if err != nil {
		t.Fatalf("RecoverKeysWith: %v", err)
	}
	if ok {
		t.Fatalf("wrong keys accepted: %+v", keys)
	}
}

// TestExternalBkcrackMiss maps a clean no-keys run (non-zero exit, no triple) to
// ok=false with no error.
func TestExternalBkcrackMiss(t *testing.T) {
	plain, cipher, _ := kpVector("hunter2", "the quick brown fox jumps over the lazy dog 0123456789")
	bin := writeStub(t, "bkcrack-miss.sh", "#!/bin/sh\necho 'Could not find the keys.' >&2\nexit 1\n")

	keys, ok, err := RecoverKeysWith(plain, cipher, ExternalBkcrack{Bin: bin})
	if err != nil {
		t.Fatalf("a clean miss should not error, got %v", err)
	}
	if ok {
		t.Fatalf("unexpected success: %+v", keys)
	}
}

// TestExternalBkcrackBinaryMissing surfaces an unrunnable binary as an error.
func TestExternalBkcrackBinaryMissing(t *testing.T) {
	plain, cipher, _ := kpVector("hunter2", "the quick brown fox jumps over the lazy dog 0123456789")
	_, ok, err := RecoverKeysWith(plain, cipher, ExternalBkcrack{Bin: filepath.Join(t.TempDir(), "does-not-exist")})
	if ok {
		t.Fatal("unexpected success")
	}
	if err == nil {
		t.Fatal("expected an error for a missing binary")
	}
}

// TestRecoverKeysWithNilOffloader guards the nil case.
func TestRecoverKeysWithNilOffloader(t *testing.T) {
	plain, cipher, _ := kpVector("hunter2", "the quick brown fox jumps over the lazy dog 0123456789")
	if _, ok, err := RecoverKeysWith(plain, cipher, nil); ok || err == nil {
		t.Fatalf("nil offloader: ok=%v err=%v", ok, err)
	}
}

// TestParseBkcrackKeys checks the parser directly, including taking the last
// triple when several are printed.
func TestParseBkcrackKeys(t *testing.T) {
	out := []byte("[11:22:33] Z reduction using 10 bytes\n" +
		"11111111 22222222 33333333\n" +
		"[11:22:34] Keys\n" +
		"aabbccdd 01020304 0a0b0c0d\n")
	k, ok := parseBkcrackKeys(out)
	if !ok {
		t.Fatal("parse failed")
	}
	want := Keys{k0: 0xaabbccdd, k1: 0x01020304, k2: 0x0a0b0c0d}
	if k != want {
		t.Fatalf("parsed %+v, want %+v", k, want)
	}
	if _, ok := parseBkcrackKeys([]byte("no keys here\n")); ok {
		t.Fatal("parsed keys from output with none")
	}
}
