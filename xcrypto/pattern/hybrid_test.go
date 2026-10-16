package pattern

import (
	"io"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

func drainHybrid(t *testing.T, s candidates.Source) []string {
	t.Helper()
	var out []string
	for {
		b, err := s.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		out = append(out, string(b))
	}
	return out
}

func TestHybridAppend(t *testing.T) {
	m, err := CompileMask("?d", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := Hybrid(candidates.Explicit("ab", "cd"), m, true)
	if got := h.Len(); got != 20 {
		t.Fatalf("Len = %d, want 20", got)
	}
	got := drainHybrid(t, h)
	want := []string{"ab0", "ab1", "ab2", "ab3", "ab4", "ab5", "ab6", "ab7", "ab8", "ab9",
		"cd0", "cd1", "cd2", "cd3", "cd4", "cd5", "cd6", "cd7", "cd8", "cd9"}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestHybridPrepend(t *testing.T) {
	m, err := CompileMask("?d?d", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := Hybrid(candidates.Explicit("x"), m, false)
	got := drainHybrid(t, h)
	if len(got) != 100 {
		t.Fatalf("got %d, want 100", len(got))
	}
	if got[0] != "00x" || got[99] != "99x" {
		t.Fatalf("bounds: first=%q last=%q", got[0], got[99])
	}
}

func TestHybridResetAndClone(t *testing.T) {
	m, _ := CompileMask("?d", nil)
	h := Hybrid(candidates.Explicit("ab", "cd"), m, true)
	first := drainHybrid(t, h)
	if err := h.Reset(); err != nil {
		t.Fatal(err)
	}
	again := drainHybrid(t, h)
	if len(first) != len(again) || first[0] != again[0] || first[len(first)-1] != again[len(again)-1] {
		t.Fatal("Reset did not restart iteration")
	}
	cl, ok := h.(candidates.Cloner)
	if !ok {
		t.Fatal("hybrid should be cloneable over an explicit wordlist")
	}
	c := cl.CloneSource()
	if c == nil {
		t.Fatal("CloneSource returned nil")
	}
	if got := drainHybrid(t, c); len(got) != 20 {
		t.Fatalf("clone produced %d, want 20", len(got))
	}
}

func TestHybridEmptyMask(t *testing.T) {
	// A mask that compiles to zero positions yields a single empty expansion,
	// so dict+mask degenerates to the wordlist itself.
	m, err := CompileMask("", nil)
	if err != nil {
		t.Fatal(err)
	}
	h := Hybrid(candidates.Explicit("a", "b"), m, true)
	got := drainHybrid(t, h)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("empty mask: got %v", got)
	}
}
