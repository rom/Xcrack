package candidates

import (
	"io"
	"testing"
)

// TestSwedishList checks the embedded Swedish wordlist loads, is sizable,
// deduplicated, and leads with high-yield bare passwords.
func TestSwedishList(t *testing.T) {
	if n := SwedishLen(); n < 10000 {
		t.Fatalf("Swedish list has %d entries, want a sizable (>=10k) list", n)
	}
	src := Swedish()
	seen := make(map[string]struct{})
	var count int
	var first string
	for {
		b, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		s := string(b)
		if s == "" {
			t.Fatal("empty candidate in the Swedish list")
		}
		if _, dup := seen[s]; dup {
			t.Fatalf("duplicate candidate %q in the Swedish list", s)
		}
		seen[s] = struct{}{}
		if count == 0 {
			first = s
		}
		count++
	}
	if first != "lösenord" {
		t.Errorf("first entry = %q, want the highest-yield bare password first", first)
	}
	// A few representative entries must be present.
	for _, want := range []string{"sommar", "Stockholm", "midsommar", "sommar2024"} {
		if _, ok := seen[want]; !ok {
			t.Errorf("expected %q in the Swedish list", want)
		}
	}
}

// TestSwedishClone ensures the source clones for the engine's sibling parallelism.
func TestSwedishClone(t *testing.T) {
	c, ok := Swedish().(Cloner)
	if !ok || c.CloneSource() == nil {
		t.Fatal("Swedish() must be cloneable")
	}
}
