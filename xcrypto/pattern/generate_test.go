package pattern

import "testing"

func TestGenerateRulesValidAndDeterministic(t *testing.T) {
	a := GenerateRules(200, 42)
	b := GenerateRules(200, 42)
	if len(a) == 0 {
		t.Fatal("no rules generated")
	}
	// Deterministic for a fixed seed.
	if len(a) != len(b) {
		t.Fatalf("non-deterministic length: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic at %d: %q vs %q", i, a[i], b[i])
		}
	}
	// Distinct.
	seen := map[string]bool{}
	for _, l := range a {
		if seen[l] {
			t.Errorf("duplicate rule %q", l)
		}
		seen[l] = true
	}
	// Every generated line compiles and applies without panicking.
	rs, err := CompileRules(a)
	if err != nil {
		t.Fatalf("generated rules failed to compile: %v", err)
	}
	if rs.Len() == 0 {
		t.Fatal("compiled ruleset empty")
	}
	for _, w := range [][]byte{[]byte("password"), []byte(""), []byte("a")} {
		_ = rs.Apply(w) // must not panic
	}
	// A different seed gives a different set (overwhelmingly likely).
	c := GenerateRules(200, 7)
	if len(c) == len(a) {
		same := true
		for i := range a {
			if a[i] != c[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("different seed produced identical rules")
		}
	}
}

func TestGenerateRulesZero(t *testing.T) {
	if r := GenerateRules(0, 1); r != nil {
		t.Errorf("expected nil for n=0, got %v", r)
	}
}
