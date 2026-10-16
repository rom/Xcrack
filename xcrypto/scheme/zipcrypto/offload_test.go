package zipcrypto

import (
	"fmt"
	"os"
	"os/exec"
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
// as of before plain[0] (the initial NewKeys state, since Encrypt consumes
// plain[0] first).
func kpVector(pw, text string) (plain, cipher []byte, want Keys) {
	plain = []byte(text)
	cipher = append([]byte(nil), plain...)
	ek := NewKeys([]byte(pw))
	ek.Encrypt(cipher)
	return plain, cipher, NewKeys([]byte(pw))
}

// bkHex returns the "X Y Z" hex a real bkcrack run (via ExternalBkcrack's dummy
// 12-byte header) would print for keys `want`: the state BEFORE that header,
// which ExternalBkcrack then rolls forward to recover `want`.
func bkHex(want Keys) string {
	bk, _ := want.RollBack(make([]byte, HeaderLen))
	k0, k1, k2 := bk.Words()
	return fmt.Sprintf("%08x %08x %08x", k0, k1, k2)
}

// TestExternalBkcrackOffload drives RecoverKeysWith through a stub that mimics
// bkcrack's output and header convention, then confirms the recovered keys
// decrypt the data.
func TestExternalBkcrackOffload(t *testing.T) {
	plain, cipher, want := kpVector("hunter2", "the quick brown fox jumps over the lazy dog 0123456789")
	body := fmt.Sprintf("#!/bin/sh\necho '[12:00:00] Keys'\necho '%s'\n", bkHex(want))
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
	body := fmt.Sprintf("#!/bin/sh\necho 'Keys: %s'\n", bkHex(want))
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
// false positive: a stub that prints keys which do not reproduce the keystream
// must yield not-found, not a wrong "success".
func TestExternalBkcrackWrongKeysRejected(t *testing.T) {
	plain, cipher, want := kpVector("hunter2", "the quick brown fox jumps over the lazy dog 0123456789")
	bad := KeysFromWords(0xdeadbeef, 0xfeedface, 0x12345678)
	_ = want
	body := fmt.Sprintf("#!/bin/sh\necho 'Keys'\necho '%s'\n", bkHex(bad))
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

// TestExternalBkcrackReal cross-validates the offload against a REAL bkcrack
// binary, when one is supplied via XCRACK_BKCRACK. It is the oracle check for
// ExternalBkcrack's header/offset bridging AND for this package's own ZipCrypto
// primitives: bkcrack's recovered state, rolled forward through the dummy header,
// must equal NewKeys(pw) and must decrypt the data. A stub cannot prove the
// dummy-header convention is right — only the genuine tool can. Skipped when the
// env var is unset so CI without bkcrack still passes.
//
// This does NOT run the in-process search (that can take tens of minutes on a
// full keyspace); the in-process attack's correctness is covered by
// TestAutoPipelineRecovers and the full-run benchmark, both of which land on the
// same NewKeys(pw) that bkcrack reports here.
func TestExternalBkcrackReal(t *testing.T) {
	bin := os.Getenv("XCRACK_BKCRACK")
	if bin == "" {
		t.Skip("set XCRACK_BKCRACK to a bkcrack binary to run the oracle cross-check")
	}
	if _, err := exec.LookPath(bin); err != nil {
		if _, statErr := os.Stat(bin); statErr != nil {
			t.Skipf("XCRACK_BKCRACK=%q not executable: %v", bin, err)
		}
	}
	for _, pw := range []string{"hunter2", "S3cr3t!", "correct horse battery staple"} {
		plain, cipher, want := kpVector(pw, "the quick brown fox jumps over the lazy dog 0123456789 and then some")
		keys, ok, err := RecoverKeysWith(plain, cipher, ExternalBkcrack{Bin: bin})
		if err != nil {
			t.Fatalf("pw=%q: real bkcrack: %v", pw, err)
		}
		if !ok {
			t.Fatalf("pw=%q: real bkcrack found no keys", pw)
		}
		if keys != want {
			t.Fatalf("pw=%q: bkcrack keys %+v != NewKeys %+v", pw, keys, want)
		}
		dec := append([]byte(nil), cipher...)
		keys.Decrypt(dec)
		if string(dec) != string(plain) {
			t.Fatalf("pw=%q: bkcrack keys do not decrypt the data", pw)
		}
	}
}
