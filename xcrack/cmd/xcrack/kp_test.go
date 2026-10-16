package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/rom/xcrypto/scheme/zipcrypto"
)

// stubBkcrack writes an executable shell script that prints keys in bkcrack's
// output format (a "Keys" banner then an "X Y Z" line). keys is the state bkcrack
// would report: before the 12-byte dummy header ExternalBkcrack prepends.
func stubBkcrack(t *testing.T, keys zipcrypto.Keys) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub uses /bin/sh")
	}
	k0, k1, k2 := keys.Words()
	body := fmt.Sprintf("#!/bin/sh\necho '[00:00:00] Keys'\necho '%08x %08x %08x'\n", k0, k1, k2)
	p := filepath.Join(t.TempDir(), "bkstub.sh")
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// kpEntry builds a full ZipCrypto entry (12-byte header + encrypted data) plus
// the known-plaintext window at data offset `off`, and the bkcrack-convention
// keys a stub should emit so the offload recovers the true state.
func kpEntry(t *testing.T, pw, data string, off, n int) (dir string, dataBytes []byte, stubKeys zipcrypto.Keys) {
	t.Helper()
	dir = t.TempDir()
	dataBytes = []byte(data)
	entry := zipcrypto.EncryptRaw([]byte(pw), []byte("ABCDEFGHIJK"), 0x5a, dataBytes)

	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	write("entry.bin", entry)
	write("data.bin", dataBytes)
	write("plain.bin", dataBytes[off:off+n])
	write("cipher.bin", entry[zipcrypto.HeaderLen+off:zipcrypto.HeaderLen+off+n])

	// state before plain[0] = before entry[HeaderLen+off]
	k := zipcrypto.NewKeys([]byte(pw))
	k.Decrypt(append([]byte(nil), entry[:zipcrypto.HeaderLen+off]...))
	stubKeys, _ = k.RollBack(make([]byte, zipcrypto.HeaderLen))
	return dir, dataBytes, stubKeys
}

// TestKPDecryptRollback is the end-to-end test for `xcrack kp --decrypt`: a
// mid-entry known plaintext must recover the keys and decrypt the WHOLE entry by
// rolling the state back over the header and earlier data.
func TestKPDecryptRollback(t *testing.T) {
	dir, data, stubKeys := kpEntry(t, "hunter2",
		"STORED entry contents: the quick brown fox jumps over the lazy dog, twice over, 0123456789!!", 30, 20)
	stub := stubBkcrack(t, stubKeys)
	out := filepath.Join(dir, "out.bin")

	code := runKP([]string{
		"--plain", filepath.Join(dir, "plain.bin"),
		"--cipher", filepath.Join(dir, "cipher.bin"),
		"--offset", "30",
		"--bkcrack", stub,
		"--decrypt", filepath.Join(dir, "entry.bin"),
		"--out", out,
	})
	if code != 0 {
		t.Fatalf("runKP returned %d, want 0", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("decrypted %q, want %q", got, data)
	}
}

// TestKPKeepHeader checks --keep-header retains the 12-byte header.
func TestKPKeepHeader(t *testing.T) {
	dir, data, stubKeys := kpEntry(t, "hunter2",
		"STORED entry contents: the quick brown fox jumps over the lazy dog, twice over, 0123456789!!", 0, 16)
	stub := stubBkcrack(t, stubKeys)
	out := filepath.Join(dir, "out.bin")

	code := runKP([]string{
		"--plain", filepath.Join(dir, "plain.bin"),
		"--cipher", filepath.Join(dir, "cipher.bin"),
		"--bkcrack", stub,
		"--decrypt", filepath.Join(dir, "entry.bin"),
		"--keep-header",
		"--out", out,
	})
	if code != 0 {
		t.Fatalf("runKP returned %d, want 0", code)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(data)+zipcrypto.HeaderLen {
		t.Fatalf("keep-header output %d bytes, want %d", len(got), len(data)+zipcrypto.HeaderLen)
	}
}

// TestKPOffsetMismatch rejects an --offset that doesn't line --cipher up with the
// entry (a user error), returning exit code 2 rather than writing garbage.
func TestKPOffsetMismatch(t *testing.T) {
	dir, _, stubKeys := kpEntry(t, "hunter2",
		"STORED entry contents: the quick brown fox jumps over the lazy dog, twice over, 0123456789!!", 30, 20)
	stub := stubBkcrack(t, stubKeys)
	out := filepath.Join(dir, "out.bin")

	code := runKP([]string{
		"--plain", filepath.Join(dir, "plain.bin"),
		"--cipher", filepath.Join(dir, "cipher.bin"),
		"--offset", "31", // wrong: cipher was taken at offset 30
		"--bkcrack", stub,
		"--decrypt", filepath.Join(dir, "entry.bin"),
		"--out", out,
	})
	if code != 2 {
		t.Fatalf("runKP returned %d, want 2 (offset mismatch)", code)
	}
}

// TestKPMissingArgs rejects a call without the required --plain/--cipher.
func TestKPMissingArgs(t *testing.T) {
	if code := runKP([]string{"--offset", "0"}); code != 2 {
		t.Fatalf("runKP with no --plain/--cipher returned %d, want 2", code)
	}
}

// TestKPRecoverPasswordRequiresDecrypt rejects --recover-password without the
// context (--decrypt + --bkcrack) needed to reach the entry-start keys.
func TestKPRecoverPasswordRequiresDecrypt(t *testing.T) {
	dir, _, _ := kpEntry(t, "hunter2",
		"STORED entry contents: the quick brown fox jumps over the lazy dog 0123456789!!", 0, 16)
	code := runKP([]string{
		"--plain", filepath.Join(dir, "plain.bin"),
		"--cipher", filepath.Join(dir, "cipher.bin"),
		"--recover-password", "7:?l?d", // no --decrypt / --bkcrack
	})
	if code != 2 {
		t.Fatalf("runKP returned %d, want 2 (recover-password needs decrypt+bkcrack)", code)
	}
}

// TestKPRecoverPassword exercises the end-to-end --recover-password path with a
// stub bkcrack that emits both the key-recovery triple and the password line.
func TestKPRecoverPassword(t *testing.T) {
	const pw = "hunter2"
	dir, data, stubKeys := kpEntry(t, pw,
		"STORED entry contents: the quick brown fox jumps over the lazy dog 0123456789!!", 30, 20)
	// One stub answers both invocations: the Keys triple (for key recovery) and
	// the password bytes (for -r). Each parser ignores the other's lines.
	k0, k1, k2 := stubKeys.Words()
	var pwHex string
	for i := 0; i < len(pw); i++ {
		pwHex += fmt.Sprintf(" %02x", pw[i])
	}
	body := fmt.Sprintf("#!/bin/sh\necho 'Keys'\necho '%08x %08x %08x'\necho 'Password'\necho 'as bytes:%s'\n", k0, k1, k2, pwHex)
	if runtime.GOOS == "windows" {
		t.Skip("stub uses /bin/sh")
	}
	stub := filepath.Join(dir, "bkboth.sh")
	if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out.bin")

	// Capture stdout to read the "password: ..." line.
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	code := runKP([]string{
		"--plain", filepath.Join(dir, "plain.bin"),
		"--cipher", filepath.Join(dir, "cipher.bin"),
		"--offset", "30",
		"--bkcrack", stub,
		"--decrypt", filepath.Join(dir, "entry.bin"),
		"--recover-password", "7:?l?d",
		"--out", out,
	})
	w.Close()
	os.Stdout = old
	stdout, _ := io.ReadAll(r)

	if code != 0 {
		t.Fatalf("runKP returned %d, want 0\nstdout: %s", code, stdout)
	}
	got, err := os.ReadFile(out)
	if err != nil || string(got) != string(data) {
		t.Fatalf("decrypt mismatch (err=%v)", err)
	}
	if want := "password: " + pw; !strings.Contains(string(stdout), want) {
		t.Fatalf("stdout %q missing %q", stdout, want)
	}
}
