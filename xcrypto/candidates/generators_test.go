package candidates

import (
	"io"
	"sort"
	"testing"
)

func drainGen(t *testing.T, s Source) []string {
	t.Helper()
	var out []string
	for i := 0; i < 1<<22; i++ {
		b, err := s.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		out = append(out, string(b))
	}
	t.Fatal("source did not terminate")
	return nil
}

func TestToggleCase(t *testing.T) {
	got := drainGen(t, ToggleCase(Explicit("aB1"), 0))
	sort.Strings(got)
	want := []string{"AB1", "Ab1", "aB1", "ab1"}
	if len(got) != 4 {
		t.Fatalf("got %d variants %v, want 4", len(got), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("variant %d = %q, want %q (all: %v)", i, got[i], want[i], got)
		}
	}
	// A word with no letters yields exactly itself.
	if g := drainGen(t, ToggleCase(Explicit("123"), 0)); len(g) != 1 || g[0] != "123" {
		t.Fatalf("no-letter word: %v", g)
	}
}

func TestToggleCaseCapsLength(t *testing.T) {
	// 20 letters, cap 12 => 2^12 variants, not 2^20.
	got := drainGen(t, ToggleCase(Explicit("abcdefghijklmnopqrst"), 0))
	if len(got) != 1<<maxToggleLetters {
		t.Fatalf("got %d, want %d", len(got), 1<<maxToggleLetters)
	}
}

func TestKeyboardWalk(t *testing.T) {
	got := drainGen(t, KeyboardWalk(4, 4, 100000))
	set := map[string]bool{}
	for _, g := range got {
		if len(g) != 4 {
			t.Fatalf("walk %q not length 4", g)
		}
		set[g] = true
	}
	for _, w := range []string{"qwer", "asdf", "zxcv", "1wsx"} {
		if !set[w] {
			t.Errorf("expected straight-line walk %q to be generated", w)
		}
	}
	// A longer straight walk and its prefixes also appear.
	if g := drainGen(t, KeyboardWalk(6, 6, 100000)); len(g) == 0 {
		t.Fatal("expected length-6 walks")
	} else {
		has := false
		for _, w := range g {
			if w == "qwerty" {
				has = true
			}
		}
		if !has {
			t.Error("expected 'qwerty' among length-6 walks")
		}
	}
}

func TestKeyboardWalkBounded(t *testing.T) {
	got := drainGen(t, KeyboardWalk(1, 8, 500))
	if len(got) > 500 {
		t.Fatalf("got %d, exceeds cap 500", len(got))
	}
}

func TestPrince(t *testing.T) {
	got := drainGen(t, Prince(Explicit("ab", "cd"), 1, 4, 2, 1000))
	want := []string{"ab", "cd", "abab", "abcd", "cdab", "cdcd"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("prince[%d] = %q, want %q (all %v)", i, got[i], want[i], got)
		}
	}
}

func TestPrinceLengthFilterAndClone(t *testing.T) {
	// minLen 3 drops the single words ("ab","cd" = len 2); only 2-word chains (len 4).
	p := Prince(Explicit("ab", "cd"), 3, 4, 2, 1000)
	got := drainGen(t, p)
	if len(got) != 4 {
		t.Fatalf("got %d, want 4 (the len-4 chains): %v", len(got), got)
	}
	cl, ok := p.(Cloner)
	if !ok {
		t.Fatal("Prince should be cloneable")
	}
	if again := drainGen(t, cl.CloneSource()); len(again) != 4 {
		t.Fatalf("clone produced %d, want 4", len(again))
	}
	if err := p.Reset(); err != nil {
		t.Fatal(err)
	}
	if after := drainGen(t, p); len(after) != 4 {
		t.Fatalf("after reset %d, want 4", len(after))
	}
}
