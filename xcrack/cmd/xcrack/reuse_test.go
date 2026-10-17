package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReuseStampRoundTrip(t *testing.T) {
	out := t.TempDir()
	src := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(src, []byte("the source bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	const suffix = ".extracted"
	const sig = "sig-v1"

	// No stamp yet → miss.
	if _, ok := readReuseStamp(out, src, suffix, sig); ok {
		t.Fatal("expected miss before any stamp")
	}
	// Write a stamp, then it should hit with the recorded passwords.
	writeReuseStamp(out, src, suffix, sha256hex([]byte("the source bytes")), sig, []string{"opensesame"})
	pw, ok := readReuseStamp(out, src, suffix, sig)
	if !ok || len(pw) != 1 || pw[0] != "opensesame" {
		t.Fatalf("expected hit with [opensesame], got ok=%v pw=%v", ok, pw)
	}
	// A different candidate signature invalidates the stamp.
	if _, ok := readReuseStamp(out, src, suffix, "other-sig"); ok {
		t.Error("expected miss on changed candidate signature")
	}
	// Changed source content invalidates the stamp.
	if err := os.WriteFile(src, []byte("DIFFERENT bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := readReuseStamp(out, src, suffix, sig); ok {
		t.Error("expected miss on changed source content")
	}
}
