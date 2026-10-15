package pattern

import (
	"io"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

func drain(t *testing.T, s candidates.Source) []string {
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

func TestMaskEnumeration(t *testing.T) {
	m, err := CompileMask("?d?d", nil)
	if err != nil {
		t.Fatal(err)
	}
	if k := m.Keyspace(); k != 100 {
		t.Fatalf("keyspace = %d, want 100", k)
	}
	got := drain(t, m.Source())
	if len(got) != 100 {
		t.Fatalf("got %d candidates, want 100", len(got))
	}
	if got[0] != "00" || got[1] != "01" || got[10] != "10" || got[99] != "99" {
		t.Fatalf("unexpected order: %q %q %q %q", got[0], got[1], got[10], got[99])
	}
}

func TestMaskCustomAndLiteral(t *testing.T) {
	m, err := CompileMask("x?1", map[rune]string{'1': "ab"})
	if err != nil {
		t.Fatal(err)
	}
	got := drain(t, m.Source())
	if len(got) != 2 || got[0] != "xa" || got[1] != "xb" {
		t.Fatalf("got %v, want [xa xb]", got)
	}
}

func TestMaskErrors(t *testing.T) {
	if _, err := CompileMask("?z", nil); err == nil {
		t.Error("expected error for unknown token ?z")
	}
	if _, err := CompileMask("?1", nil); err == nil {
		t.Error("expected error for undefined custom charset ?1")
	}
}

func TestRules(t *testing.T) {
	rs, err := CompileRules([]string{":", "c", "u", "$1$2", "sa@", "r", "d"})
	if err != nil {
		t.Fatal(err)
	}
	got := rs.Apply([]byte("abc"))
	want := []string{"abc", "Abc", "ABC", "abc12", "@bc", "cba", "abcabc"}
	if len(got) != len(want) {
		t.Fatalf("got %d outputs, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("rule %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestToggleAndDeleteAt(t *testing.T) {
	rs, err := CompileRules([]string{"T0", "D1"})
	if err != nil {
		t.Fatal(err)
	}
	got := rs.Apply([]byte("abcd"))
	if string(got[0]) != "Abcd" {
		t.Errorf("T0: got %q, want Abcd", got[0])
	}
	if string(got[1]) != "acd" {
		t.Errorf("D1: got %q, want acd", got[1])
	}
}

func TestWithRules(t *testing.T) {
	base := candidates.Explicit("foo", "bar")
	rs, _ := CompileRules([]string{":", "c"})
	src := WithRules(base, rs)
	got := drain(t, src)
	want := []string{"foo", "Foo", "bar", "Bar"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("i=%d got %q want %q", i, got[i], want[i])
		}
	}
	// Reset re-iterates
	if err := src.Reset(); err != nil {
		t.Fatal(err)
	}
	if again := drain(t, src); len(again) != len(want) {
		t.Fatalf("after reset got %d, want %d", len(again), len(want))
	}
}

func TestParseTextAndCompile(t *testing.T) {
	spec, err := ParseText([]byte("# comment\ncharset1: abc\nmask: ?1?1\nrule: c\n?d\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Masks) != 2 || spec.Masks[0] != "?1?1" || spec.Masks[1] != "?d" {
		t.Fatalf("masks = %v", spec.Masks)
	}
	if len(spec.Rules) != 1 || spec.Rules[0] != "c" {
		t.Fatalf("rules = %v", spec.Rules)
	}
	set, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if set.Keyspace() != 9+10 { // ?1?1 (3*3) + ?d (10)
		t.Fatalf("keyspace = %d, want 19", set.Keyspace())
	}
	if !set.HasRules() {
		t.Fatal("expected rules")
	}
}
