package candidates

import (
	"reflect"
	"testing"
)

func TestBreachCorpusLayouts(t *testing.T) {
	// A mix of SecLists-style count-prefix, HIBP-style colon-suffix, bare words,
	// a CRLF line, a password containing a colon, and a count-only remnant.
	lines := []string{
		"3303003 123456",    // count-prefix
		"\t 120 letmein",    // leading blanks + tab
		"password:37359195", // colon-suffix
		"user:pass:12",      // colon-suffix, password keeps internal colon
		"plainword",         // bare
		"with spaces",       // bare, keeps the space (no leading digits)
		"carriage\r",        // trailing CR stripped
		"   42   ",          // count only, empty password -> skipped
		"",                  // empty -> skipped
	}
	got := drainGen(t, BreachCorpus(Explicit(lines...), 0))
	want := []string{"123456", "letmein", "password", "user:pass", "plainword", "with spaces", "carriage"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed:\n got %q\nwant %q", got, want)
	}
}

func TestBreachCorpusMinCount(t *testing.T) {
	lines := []string{
		"1000 common",
		"500 medium",
		"5 rare",
		"bareword", // no count -> kept regardless of minCount
		"mixed:3",  // colon count below threshold -> dropped
	}
	got := drainGen(t, BreachCorpus(Explicit(lines...), 100))
	want := []string{"common", "medium", "bareword"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("min-count filter:\n got %q\nwant %q", got, want)
	}
}

func TestBreachCorpusResetAndClone(t *testing.T) {
	src := BreachCorpus(Explicit("10 a", "20 b"), 0)
	first := drainGen(t, src)
	if err := src.Reset(); err != nil {
		t.Fatal(err)
	}
	again := drainGen(t, src)
	if !reflect.DeepEqual(first, again) {
		t.Fatalf("after reset %q != %q", again, first)
	}
	cl, ok := src.(Cloner)
	if !ok {
		t.Fatal("BreachCorpus over a cloneable source should be cloneable")
	}
	if c := drainGen(t, cl.CloneSource()); !reflect.DeepEqual(c, first) {
		t.Fatalf("clone %q != %q", c, first)
	}
}

func TestBreachCorpusNotCountPrefix(t *testing.T) {
	// A bare all-digit line is a password, not a count (no following blank).
	got := drainGen(t, BreachCorpus(Explicit("12345678"), 0))
	if !reflect.DeepEqual(got, []string{"12345678"}) {
		t.Fatalf("all-digit line mis-parsed: %q", got)
	}
}
