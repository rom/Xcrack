package candidates

import (
	"reflect"
	"testing"
)

func TestCombinator(t *testing.T) {
	got := drain(t, Combinator(Explicit("a", "b"), Explicit("1", "2"), nil))
	want := []string{"a1", "a2", "b1", "b2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCombinatorSeparator(t *testing.T) {
	got := drain(t, Combinator(Explicit("foo"), Explicit("bar", "baz"), []byte("-")))
	want := []string{"foo-bar", "foo-baz"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestCombinatorLenAndClone(t *testing.T) {
	c := Combinator(Explicit("a", "b", "c"), Explicit("1", "2"), nil)
	if c.Len() != 6 {
		t.Fatalf("Len = %d want 6", c.Len())
	}
	cl, ok := c.(Cloner)
	if !ok {
		t.Fatal("combinator is not a Cloner")
	}
	drain(t, c) // exhaust the original
	if got := drain(t, cl.CloneSource()); len(got) != 6 {
		t.Fatalf("clone produced %d items, want 6", len(got))
	}
}

func TestDedup(t *testing.T) {
	got := drain(t, Dedup(Explicit("a", "b", "a", "c", "b", "a")))
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMarkovGenOrdersByProbability(t *testing.T) {
	m := TrainMarkov([][]byte{
		[]byte("password"), []byte("passw0rd"), []byte("sunshine"),
		[]byte("welcome"), []byte("dragon"), []byte("football"),
	})
	gen := MarkovGen(m, 3, 6, 50)
	out := drain(t, gen)
	if len(out) == 0 {
		t.Fatal("generator produced nothing")
	}
	if len(out) > 50 {
		t.Fatalf("generator exceeded max: %d", len(out))
	}
	// Emissions should be in non-increasing probability order.
	prev := 1.0
	first := true
	for _, s := range out {
		sc := m.Score([]byte(s))
		if !first && sc > prev+1e-9 {
			t.Fatalf("out of order: %q scored %.4f after %.4f", s, sc, prev)
		}
		prev, first = sc, false
	}
	// Lengths are within range.
	for _, s := range out {
		if len(s) < 3 || len(s) > 6 {
			t.Fatalf("length out of range: %q", s)
		}
	}
}

func TestMarkovGenDeterministicAndCloneable(t *testing.T) {
	m := TrainMarkov([][]byte{[]byte("abc"), []byte("abd"), []byte("acd")})
	a := drain(t, MarkovGen(m, 2, 3, 20))
	b := drain(t, MarkovGen(m, 2, 3, 20))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("generator is not deterministic")
	}
	g := MarkovGen(m, 2, 3, 20)
	cl, ok := g.(Cloner)
	if !ok {
		t.Fatal("generator is not a Cloner")
	}
	if got := drain(t, cl.CloneSource()); !reflect.DeepEqual(got, a) {
		t.Fatal("clone differs from original")
	}
}
