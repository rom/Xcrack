package main

import (
	"path/filepath"
	"testing"
)

func TestSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.session")
	s := loadSession(path, "sig-A")
	if _, done := s.get("a.zip"); done {
		t.Fatal("fresh session should have nothing done")
	}
	s.markDone("a.zip", []string{"hunter2"})
	s.markDone("b.zip", nil) // searched, no password

	// Reload with the matching signature: both entries survive.
	s2 := loadSession(path, "sig-A")
	if pw, done := s2.get("a.zip"); !done || len(pw) != 1 || pw[0] != "hunter2" {
		t.Fatalf("a.zip = (%v,%v), want ([hunter2],true)", pw, done)
	}
	if pw, done := s2.get("b.zip"); !done || len(pw) != 0 {
		t.Fatalf("b.zip = (%v,%v), want ([],true)", pw, done)
	}

	// A changed candidate signature starts fresh (stale session discarded).
	s3 := loadSession(path, "sig-B")
	if _, done := s3.get("a.zip"); done {
		t.Fatal("signature mismatch should start a fresh session")
	}
}
