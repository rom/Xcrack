package candidates

import (
	"io"
	"testing"
)

func drain(t *testing.T, s Source) []string {
	t.Helper()
	var out []string
	for {
		v, err := s.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(v))
	}
}

func TestCloneIndependent(t *testing.T) {
	base := Chain(Explicit("a", "b"), DefaultList())
	c, ok := base.(Cloner)
	if !ok {
		t.Fatal("Chain(Explicit, DefaultList) should be cloneable")
	}
	clone := c.CloneSource()
	if clone == nil {
		t.Fatal("clone is nil")
	}
	// Advance the clone; the original must be unaffected.
	clone.Next()
	clone.Next()
	got := drain(t, base)
	if len(got) < 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("original iteration affected by clone: %v", got[:min(3, len(got))])
	}
}

func TestStdinNotCloneable(t *testing.T) {
	c, ok := Stdin().(Cloner)
	if !ok {
		t.Skip("Stdin does not expose Cloner")
	}
	if c.CloneSource() != nil {
		t.Fatal("Stdin must not be cloneable (one-shot stream)")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
