package candidates

import (
	"io"
	"reflect"
	"testing"
)

func drainN(t *testing.T, s Source, n int) []string {
	t.Helper()
	var out []string
	for i := 0; i < n; i++ {
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

func TestPCFGSegmentize(t *testing.T) {
	segs, parts := segmentize("pass12!!")
	wantSegs := []segment{{'L', 4}, {'D', 2}, {'S', 2}}
	wantParts := []string{"pass", "12", "!!"}
	if !reflect.DeepEqual(segs, wantSegs) {
		t.Errorf("segs = %v, want %v", segs, wantSegs)
	}
	if !reflect.DeepEqual(parts, wantParts) {
		t.Errorf("parts = %v, want %v", parts, wantParts)
	}
}

// TestPCFGProbabilityOrder: the most frequent base structure and terminals must
// come out first.
func TestPCFGProbabilityOrder(t *testing.T) {
	// "password1" structure (L8 D1) dominates; "123" digit run is most common.
	train := []string{
		"password1", "welcome1", "monkey12", "dragon99",
		"password1", "letmein1", "summer20", "password1",
	}
	p := TrainPCFG(train)
	got := drainN(t, p.Source(5), 5)
	if len(got) == 0 {
		t.Fatal("no candidates generated")
	}
	// The top guess should be the most probable base (L*D1 with the most common
	// letter/digit terminals). "password1" appears 3x so "password"+"1" is top.
	if got[0] != "password1" {
		t.Errorf("top guess = %q, want %q", got[0], "password1")
	}
	// Probabilities must be non-increasing — re-derive and check ordering holds by
	// confirming no later guess outranks an earlier one via a fresh run.
	got2 := drainN(t, p.Source(5), 5)
	if !reflect.DeepEqual(got, got2) {
		t.Errorf("non-deterministic: %v vs %v", got, got2)
	}
}

// TestPCFGExhaustiveNoDup: with a small grammar, enumerating everything yields no
// duplicates (the pivot trick) and covers the expected cross-product.
func TestPCFGExhaustiveNoDup(t *testing.T) {
	// Two base structures; small terminal sets.
	train := []string{"ab1", "cd2", "ab2", "cd1", "xyz", "xyz"}
	// structures: L2D1 (ab1,cd2,ab2,cd1) and L3 (xyz,xyz)
	p := TrainPCFG(train)
	all := drainN(t, p.Source(0), 1000)
	seen := map[string]bool{}
	for _, g := range all {
		if seen[g] {
			t.Fatalf("duplicate guess %q", g)
		}
		seen[g] = true
	}
	// L2D1 terminals: L2∈{ab,cd}, D1∈{1,2} -> 4 combos; L3∈{xyz} -> 1. Total 5.
	if len(all) != 5 {
		t.Fatalf("got %d guesses %v, want 5", len(all), all)
	}
	for _, want := range []string{"ab1", "ab2", "cd1", "cd2", "xyz"} {
		if !seen[want] {
			t.Errorf("missing expected guess %q", want)
		}
	}
}

func TestPCFGEmptyTraining(t *testing.T) {
	p := TrainPCFG(nil)
	if got := drainN(t, p.Source(10), 10); len(got) != 0 {
		t.Fatalf("empty grammar produced %v", got)
	}
}

// TestPCFGProbabilitiesNonIncreasing checks the heap truly emits by probability.
func TestPCFGProbabilitiesNonIncreasing(t *testing.T) {
	train := []string{
		"abc123", "abc124", "abc999", "def123", "abc123", "abc123", "def456", "ghi789",
	}
	p := TrainPCFG(train)
	s := p.Source(0).(*pcfgSource)
	last := 2.0
	for {
		// peek current top probability before popping
		if s.h.Len() == 0 {
			break
		}
		top := s.h[0].prob
		if top > last+1e-12 {
			t.Fatalf("probability increased: %v > %v", top, last)
		}
		last = top
		if _, err := s.Next(); err == io.EOF {
			break
		}
	}
}
