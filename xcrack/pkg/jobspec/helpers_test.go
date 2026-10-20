package jobspec

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseIncrement(t *testing.T) {
	cases := []struct {
		in       string
		min, max int
		wantErr  bool
	}{
		{"", 0, 0, false},        // unset: no increment
		{"3", 3, 3, false},       // single length
		{"2:4", 2, 4, false},     // colon range
		{"2-5", 2, 5, false},     // dash range
		{" 1 : 8 ", 1, 8, false}, // whitespace tolerated
		{"0", 0, 0, true},        // min must be >= 1
		{"5:2", 0, 0, true},      // max < min
		{"abc", 0, 0, true},      // non-numeric
		{"2:x", 0, 0, true},      // non-numeric max
	}
	for _, c := range cases {
		min, max, err := parseIncrement(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseIncrement(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && (min != c.min || max != c.max) {
			t.Errorf("parseIncrement(%q) = (%d,%d), want (%d,%d)", c.in, min, max, c.min, c.max)
		}
	}
}

func TestCompileMasks(t *testing.T) {
	ms, err := compileMasks([]string{"?d?d", "?l?u"}, nil)
	if err != nil {
		t.Fatalf("compileMasks(valid): %v", err)
	}
	if len(ms) != 2 {
		t.Fatalf("compiled %d masks, want 2", len(ms))
	}
	if _, err := compileMasks([]string{"?z"}, nil); err == nil {
		t.Fatal("compileMasks(bad mask) = nil error, want failure")
	}
}

func TestPasswordsFromFiles(t *testing.T) {
	dir := t.TempDir()
	p1 := filepath.Join(dir, "a.txt")
	p2 := filepath.Join(dir, "b.txt")
	if err := os.WriteFile(p1, []byte("alpha\nbeta\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p2, []byte("gamma\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := passwordsFromFiles([]string{p1, p2})
	if err != nil {
		t.Fatalf("passwordsFromFiles: %v", err)
	}
	want := []string{"alpha", "beta", "gamma"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, err := passwordsFromFiles([]string{filepath.Join(dir, "nope.txt")}); err == nil {
		t.Fatal("passwordsFromFiles(missing) = nil error, want failure")
	}
}

func TestCollectTrainingWords(t *testing.T) {
	dir := t.TempDir()
	wl := filepath.Join(dir, "wl.txt")
	if err := os.WriteFile(wl, []byte("w1\nw2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// explicit + wordlist, stdin ("-") skipped, blank entries dropped.
	got := collectTrainingWords([]string{"p1", "", "p2"}, false, []string{"-", wl}, 10)
	want := []string{"p1", "p2", "w1", "w2"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("collectTrainingWords = %q, want %q", got, want)
	}
	// the max cap stops collection.
	if capped := collectTrainingWords([]string{"p1", "p2"}, false, []string{wl}, 3); len(capped) != 3 {
		t.Fatalf("capped length = %d, want 3", len(capped))
	}
	// trainingSamples mirrors it as [][]byte.
	s := trainingSamples([]string{"x"}, false, nil)
	if len(s) != 1 || string(s[0]) != "x" {
		t.Fatalf("trainingSamples = %q, want [x]", s)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "job.yaml")
	if err := os.WriteFile(p, []byte("candidates:\n  wordlists: [rockyou.txt]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := LoadFile(p)
	if err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if len(s.Candidates.Wordlists) != 1 || s.Candidates.Wordlists[0] != "rockyou.txt" {
		t.Fatalf("wordlists = %v, want [rockyou.txt]", s.Candidates.Wordlists)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("LoadFile(missing) = nil error, want failure")
	}
}
