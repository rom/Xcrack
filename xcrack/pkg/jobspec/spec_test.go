package jobspec

import (
	"strings"
	"testing"
)

func TestParseLenientIgnoresUnknown(t *testing.T) {
	// A typo'd / unknown key is silently ignored by the lenient Parse, matching
	// the CLI's long-standing --config behaviour.
	y := "candidates:\n  wordlists: [a.txt]\n  not_a_real_key: true\n"
	s, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(s.Candidates.Wordlists) != 1 || s.Candidates.Wordlists[0] != "a.txt" {
		t.Fatalf("wordlists = %v, want [a.txt]", s.Candidates.Wordlists)
	}
}

func TestParseStrictRejectsUnknown(t *testing.T) {
	y := "candidates:\n  wordlists: [a.txt]\n  not_a_real_key: true\n"
	if _, err := ParseStrict([]byte(y)); err == nil {
		t.Fatal("ParseStrict accepted an unknown key, want an error")
	}
	// The empty document is a valid all-defaults job under strict parsing.
	if _, err := ParseStrict(nil); err != nil {
		t.Fatalf("ParseStrict(empty): %v", err)
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	var s Spec
	s.Candidates.Wordlists = []string{"rockyou.txt"}
	s.Candidates.Passwords = []string{"hunter2"}
	s.Patterns.Masks = []string{"?d?d?d?d"}
	s.Search.Markov = true
	s.Search.Increment = "1:4"
	s.Concurrency.Workers = 8
	s.Limits.MaxNodes = 500
	tru := true
	s.Recursion.Recurse = &tru

	data, err := s.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := ParseStrict(data)
	if err != nil {
		t.Fatalf("ParseStrict(marshalled): %v", err)
	}
	if got.Candidates.Wordlists[0] != "rockyou.txt" ||
		got.Candidates.Passwords[0] != "hunter2" ||
		got.Patterns.Masks[0] != "?d?d?d?d" ||
		!got.Search.Markov ||
		got.Search.Increment != "1:4" ||
		got.Concurrency.Workers != 8 ||
		got.Limits.MaxNodes != 500 ||
		got.Recursion.Recurse == nil || !*got.Recursion.Recurse {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestDefaults(t *testing.T) {
	var s Spec // zero value
	if !s.recurse() {
		t.Error("recurse default should be true")
	}
	if !s.promote() {
		t.Error("promote default should be true")
	}
	if !s.useDefaultList() {
		t.Error("useDefaultList default should be true")
	}
	no := false
	s.Recursion.Recurse = &no
	s.Search.Promote = &no
	s.Candidates.UseDefaultList = &no
	if s.recurse() || s.promote() || s.useDefaultList() {
		t.Error("explicit false should disable each toggle")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Spec)
		wantErr string
	}{
		{"ok empty", func(*Spec) {}, ""},
		{"bad shard", func(s *Spec) { s.Search.Shard = "3/2" }, "shard"},
		{"bad increment", func(s *Spec) { s.Search.Increment = "0:3" }, "increment"},
		{"combinator half", func(s *Spec) { s.Search.Combinator.Left = "l.txt" }, "combinator"},
		{"bad order", func(s *Spec) { s.Search.Order = "zonk" }, "order"},
		{"bad encoding", func(s *Spec) { s.Candidates.Encoding = "ebcdic" }, "encoding"},
		{"bad as", func(s *Spec) { s.Input.As = "nope" }, "as"},
		{"bad format", func(s *Spec) { s.Output.Format = "xml" }, "format"},
		{"bad per_file", func(s *Spec) { s.Budget.PerFile = "soon" }, "per_file"},
		{"good combinator", func(s *Spec) { s.Search.Combinator.Left = "l"; s.Search.Combinator.Right = "r" }, ""},
		{"good as", func(s *Spec) { s.Input.As = "sqlcipher" }, ""},
		{"good order", func(s *Spec) { s.Search.Order = "markov" }, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s Spec
			tc.mutate(&s)
			err := s.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
