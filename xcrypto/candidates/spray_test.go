package candidates

import (
	"strings"
	"testing"
)

func sprayedSet(t *testing.T, s Source) map[string]bool {
	t.Helper()
	set := map[string]bool{}
	for _, g := range drainGen(t, s) {
		set[g] = true
	}
	return set
}

func TestSprayTokensAndYears(t *testing.T) {
	set := sprayedSet(t, Spray([]string{"Acme"}, []int{2024}, 0))
	for _, want := range []string{
		"password",     // curated common
		"Welcome1",     // curated common
		"Acme2024",     // token + year
		"Acme2024!",    // token + year + bang
		"Acme@2024",    // token + @year
		"acme123",      // lower variant + suffix
		"ACME1",        // upper variant + suffix
		"Summer2024",   // seasonal
		"December2024", // monthly
	} {
		if !set[want] {
			t.Errorf("spray set missing %q", want)
		}
	}
}

func TestSprayDeterministicAndDeduped(t *testing.T) {
	a := drainGen(t, Spray([]string{"Acme"}, []int{2024, 2023}, 0))
	b := drainGen(t, Spray([]string{"Acme"}, []int{2024, 2023}, 0))
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Fatal("Spray output is not deterministic for fixed tokens+years")
	}
	seen := map[string]bool{}
	for _, g := range a {
		if seen[g] {
			t.Fatalf("duplicate in spray set: %q", g)
		}
		seen[g] = true
	}
}

func TestSprayBounded(t *testing.T) {
	got := drainGen(t, Spray([]string{"Acme", "Globex", "Initech"}, []int{2024, 2023, 2022}, 50))
	if len(got) > 50 {
		t.Fatalf("spray produced %d, exceeds cap 50", len(got))
	}
}

func TestSprayNoTokensDefaultYears(t *testing.T) {
	// No tokens, default (current/previous) years: still non-empty and includes
	// the curated common set plus seasonal walks.
	got := drainGen(t, Spray(nil, nil, 0))
	if len(got) == 0 {
		t.Fatal("empty spray set")
	}
	set := map[string]bool{}
	for _, g := range got {
		set[g] = true
	}
	if !set["123456"] || !set["Welcome1"] {
		t.Error("default spray set missing curated common passwords")
	}
}

func TestSprayCommon(t *testing.T) {
	got := drainGen(t, SprayCommon())
	if len(got) != len(sprayCommon) {
		t.Fatalf("SprayCommon = %d items, want %d", len(got), len(sprayCommon))
	}
	if got[0] != sprayCommon[0] {
		t.Errorf("order not preserved: %q", got[0])
	}
}

func TestSprayCaseHelpers(t *testing.T) {
	cases := []struct{ in, title, lower, upper string }{
		{"acme", "Acme", "acme", "ACME"},
		{"ACME", "Acme", "acme", "ACME"},
		{"aCmE", "Acme", "acme", "ACME"},
		{"123abc", "123Abc", "123abc", "123ABC"},
	}
	for _, c := range cases {
		if g := titleCase(c.in); g != c.title {
			t.Errorf("titleCase(%q) = %q, want %q", c.in, g, c.title)
		}
		if g := lowerASCII(c.in); g != c.lower {
			t.Errorf("lowerASCII(%q) = %q, want %q", c.in, g, c.lower)
		}
		if g := upperASCII(c.in); g != c.upper {
			t.Errorf("upperASCII(%q) = %q, want %q", c.in, g, c.upper)
		}
	}
}
