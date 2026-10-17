package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReuseStampRoundTripNewline guards the stamp encoding fix: a recovered
// password containing a newline (or other control bytes) must round-trip
// through write → read exactly, not be split across lines and truncated.
func TestReuseStampRoundTripNewline(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	src := filepath.Join(dir, "secret.zip")
	content := []byte("the source bytes")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}

	const suffix = ".extracted"
	sig := "sig123"
	want := []string{"plain", "has\nnewline", "tab\tand\"quote", "trailing\r"}
	writeReuseStamp(out, src, suffix, sha256hex(content), sig, want)

	got, ok := readReuseStamp(out, src, suffix, sig)
	if !ok {
		t.Fatal("readReuseStamp: ok=false, want a valid stamp")
	}
	if len(got) != len(want) {
		t.Fatalf("got %d passwords %q, want %d %q", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("password %d = %q, want %q", i, got[i], want[i])
		}
	}

	// A changed candidate signature invalidates the stamp.
	if _, ok := readReuseStamp(out, src, suffix, "other"); ok {
		t.Error("stamp should not match a different signature")
	}
}
