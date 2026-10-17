package archive

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rom/xfileformats"
)

// TestRAR5FastVerify generates RAR5 archives with the real `rar` tool and checks
// the format's fast (password-check-value) verifier: the correct password
// verifies, a wrong one does not, and the entry advertises the rar5 scheme
// (proving the crypt record parsed, so no trial decryption was needed). Covers
// both header-encrypted (-hp) and data-only (-p) archives. Skipped when `rar`
// is not installed.
func TestRAR5FastVerify(t *testing.T) {
	rarBin, err := exec.LookPath("rar")
	if err != nil {
		t.Skip("rar CLI not available")
	}
	dir := t.TempDir()
	payload := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(payload, []byte("rar5 fast-verify payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const pw = "Midsommar2024!"
	for _, tc := range []struct {
		name, flag string
	}{
		{"hp", "-hp" + pw},
		{"p", "-p" + pw},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arc := filepath.Join(dir, tc.name+".rar")
			if out, err := exec.Command(rarBin, "a", tc.flag, "-idq", arc, payload).CombinedOutput(); err != nil {
				t.Fatalf("rar a: %v\n%s", err, out)
			}
			data, err := os.ReadFile(arc)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := rarFormat{}.Entries(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("Entries: %v", err)
			}
			var enc *entryUnderTest
			for _, e := range entries {
				if e.Encrypted && e.Verify != nil {
					enc = &entryUnderTest{verify: e.Verify, scheme: schemeOf(e)}
					break
				}
			}
			if enc == nil {
				t.Fatalf("no encrypted entry with a verifier (%d entries)", len(entries))
			}
			if enc.scheme != "rar5" {
				t.Fatalf("scheme = %q, want rar5 (fast path not taken)", enc.scheme)
			}
			if ok, err := enc.verify([]byte(pw)); err != nil || !ok {
				t.Fatalf("Verify(correct) = (%v,%v), want (true,nil)", ok, err)
			}
			if ok, _ := enc.verify([]byte("definitely-wrong")); ok {
				t.Fatal("Verify(wrong) = true, want false")
			}
		})
	}
}

type entryUnderTest struct {
	verify func([]byte) (bool, error)
	scheme string
}

func schemeOf(e *xfileformats.Entry) string {
	if e.Challenge != nil {
		return e.Challenge.Scheme
	}
	return ""
}
