package candidates

import (
	"fmt"
	"io"
	"path/filepath"
	"testing"
)

func drainAll(t *testing.T, s Source) []string {
	t.Helper()
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	var out []string
	for {
		b, err := s.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(b))
	}
	return out
}

func makeList(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("cand%06d", i)
	}
	return out
}

// TestCheckpointResumePosition: after a partial run, a new wrapper on the same
// file resumes a margin behind the saved position, covering the remainder with
// no gap (only the margin is re-tested).
func TestCheckpointResumePosition(t *testing.T) {
	items := makeList(1000)
	path := filepath.Join(t.TempDir(), "ck")
	const every, margin = 50, 10

	// First run: consume 250 candidates, then persist (simulating progress).
	c1, err := Checkpoint(Explicit(items...), path, "sig-A", every, margin)
	if err != nil {
		t.Fatal(err)
	}
	if err := c1.Reset(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 250; i++ {
		if _, err := c1.Next(); err != nil {
			t.Fatal(err)
		}
	}
	c1.(Saver).Save()

	// Resume: a fresh wrapper should start at 250-margin = 240.
	c2, err := Checkpoint(Explicit(items...), path, "sig-A", every, margin)
	if err != nil {
		t.Fatal(err)
	}
	if rf := c2.(Resumable).ResumeFrom(); rf != 240 {
		t.Fatalf("ResumeFrom = %d, want 240", rf)
	}
	got := drainAll(t, c2)
	if len(got) == 0 || got[0] != items[240] {
		t.Fatalf("resume first candidate = %q, want %q", got[0], items[240])
	}
	if got[len(got)-1] != items[999] {
		t.Fatalf("resume last candidate = %q, want %q", got[len(got)-1], items[999])
	}
	if len(got) != 1000-240 {
		t.Fatalf("resume produced %d candidates, want %d", len(got), 1000-240)
	}
}

// TestCheckpointSignatureMismatch: a changed keyspace signature discards the old
// position and starts fresh.
func TestCheckpointSignatureMismatch(t *testing.T) {
	items := makeList(100)
	path := filepath.Join(t.TempDir(), "ck")
	c1, _ := Checkpoint(Explicit(items...), path, "sig-A", 10, 2)
	c1.Reset()
	for i := 0; i < 50; i++ {
		c1.Next()
	}
	c1.(Saver).Save()

	c2, _ := Checkpoint(Explicit(items...), path, "sig-DIFFERENT", 10, 2)
	if rf := c2.(Resumable).ResumeFrom(); rf != 0 {
		t.Fatalf("mismatched signature should start fresh, ResumeFrom = %d", rf)
	}
	if got := drainAll(t, c2); len(got) != 100 {
		t.Fatalf("fresh run produced %d, want 100", len(got))
	}
}

// TestCheckpointNotCloneable: the wrapper must not be cloneable, so the engine
// keeps it to a single feeder (its position is a single global cursor).
func TestCheckpointNotCloneable(t *testing.T) {
	c, _ := Checkpoint(Explicit("a", "b"), filepath.Join(t.TempDir(), "ck"), "s", 0, -1)
	if _, ok := c.(Cloner); ok {
		t.Fatal("checkpoint source must not implement Cloner")
	}
}

// TestCheckpointSeeksOnlyOnFirstReset: the resume seek happens on the first Reset
// only, so a second pass (e.g. a later container node) starts from the beginning
// rather than cascade-skipping.
func TestCheckpointSeeksOnlyOnFirstReset(t *testing.T) {
	items := makeList(1000)
	path := filepath.Join(t.TempDir(), "ck")
	c1, _ := Checkpoint(Explicit(items...), path, "s", 50, 10)
	c1.Reset()
	for i := 0; i < 300; i++ {
		c1.Next()
	}
	c1.(Saver).Save()

	c2, _ := Checkpoint(Explicit(items...), path, "s", 50, 10)
	first := drainAll(t, c2) // first Reset: resumes at 290
	if first[0] != items[290] {
		t.Fatalf("first pass resume = %q, want %q", first[0], items[290])
	}
	second := drainAll(t, c2) // second Reset: full pass from the start
	if len(second) != 1000 || second[0] != items[0] {
		t.Fatalf("second pass should be full (1000 from %q), got %d from %q", items[0], len(second), second[0])
	}
}

// TestCheckpointResumePastKeyspace: resuming past the end of a (now shorter)
// keyspace yields no candidates rather than erroring.
func TestCheckpointResumePastKeyspace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ck")
	c1, _ := Checkpoint(Explicit(makeList(500)...), path, "s", 50, 0)
	c1.Reset()
	for i := 0; i < 500; i++ {
		c1.Next()
	}
	c1.(Saver).Save()
	// Keyspace now only 100 long but checkpoint says 500.
	c2, _ := Checkpoint(Explicit(makeList(100)...), path, "s", 50, 0)
	if got := drainAll(t, c2); len(got) != 0 {
		t.Fatalf("resume past keyspace produced %d candidates, want 0", len(got))
	}
}
