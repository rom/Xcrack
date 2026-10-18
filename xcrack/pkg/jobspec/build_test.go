package jobspec

import (
	"io"
	"testing"
)

// drain collects up to cap candidates from a source, in order.
func drain(t *testing.T, src interface {
	Next() ([]byte, error)
	Reset() error
}, cap int) []string {
	t.Helper()
	if err := src.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	var out []string
	for i := 0; i < cap; i++ {
		b, err := src.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		out = append(out, string(b))
	}
	return out
}

func noDefault() *Spec {
	s := &Spec{}
	no := false
	s.Candidates.UseDefaultList = &no
	return s
}

func TestBuildOptionsMapping(t *testing.T) {
	var s Spec
	no := false
	s.Recursion.Recurse = &no
	s.Search.Promote = &no
	s.Recursion.ExplodeDocuments = true
	s.Search.Adaptive = true
	s.Search.FindAll = true
	s.Search.Context = true
	s.Concurrency.Workers = 3
	s.Concurrency.MaxProcs = 5
	s.Concurrency.FileJobs = 2
	s.Concurrency.Throttle = 40
	s.Concurrency.DualPipeline = true
	s.Limits.MaxDepth = 7
	s.Limits.MaxNodes = 11
	s.Limits.MaxCandidates = 123
	s.Budget.PerFile = "30s"
	s.Budget.Total = "5m"
	s.Input.As = "sqlcipher"

	opts, err := s.BuildOptions()
	if err != nil {
		t.Fatalf("BuildOptions: %v", err)
	}
	if !opts.NoRecurse || !opts.NoPromote || !opts.ExplodeDocuments ||
		!opts.CorpusPromotion || !opts.FindAll || !opts.ContextCandidates {
		t.Fatalf("toggle mapping wrong: %+v", opts)
	}
	if opts.Workers != 3 || opts.MaxProcs != 5 || opts.FileConcurrency != 2 ||
		opts.ThrottlePercent != 40 || !opts.DualPipeline {
		t.Fatalf("concurrency mapping wrong: %+v", opts)
	}
	if opts.Limits.MaxDepth != 7 || opts.Limits.MaxNodes != 11 || opts.Limits.MaxCandidates != 123 {
		t.Fatalf("limits mapping wrong: %+v", opts.Limits)
	}
	if opts.Budget.PerFile.String() != "30s" || opts.Budget.Total.String() != "5m0s" {
		t.Fatalf("budget mapping wrong: %+v", opts.Budget)
	}
	if opts.Registry == nil {
		t.Fatal("input.as should set a force-format registry")
	}
}

func TestBuildOptionsHintRules(t *testing.T) {
	var s Spec
	s.Search.Hint = true
	s.Search.HintRules = []string{":", "$1"} // identity + append '1'
	opts, err := s.BuildOptions()
	if err != nil {
		t.Fatalf("BuildOptions: %v", err)
	}
	if !opts.HintCandidates || opts.HintRules == nil {
		t.Fatal("hint rules not wired")
	}
	got := opts.HintRules("pw")
	// The compiled ruleset should at least produce the appended variant.
	found := false
	for _, v := range got {
		if v == "pw1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hint rules = %v, want to contain pw1", got)
	}
}

func TestBuildOptionsRejectsBadInput(t *testing.T) {
	var s Spec
	s.Input.As = "bogus"
	if _, err := s.BuildOptions(); err == nil {
		t.Fatal("BuildOptions accepted a bogus input.as")
	}
	s = Spec{}
	s.Budget.PerFile = "nope"
	if _, err := s.BuildOptions(); err == nil {
		t.Fatal("BuildOptions accepted a bad per_file duration")
	}
}

func TestCandidatesExplicitOrderAndKeyspace(t *testing.T) {
	s := noDefault()
	s.Candidates.Passwords = []string{"alpha", "beta", "gamma"}
	a, err := NewAssembler(s, Runtime{PriorityPasswords: []string{"first"}})
	if err != nil {
		t.Fatalf("NewAssembler: %v", err)
	}
	src := a.Candidates("file.zip")
	if got := src.Len(); got != 4 {
		t.Fatalf("keyspace = %d, want 4", got)
	}
	got := drain(t, src, 100)
	want := []string{"first", "alpha", "beta", "gamma"}
	if len(got) != len(want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate %d = %q, want %q (priority first)", i, got[i], want[i])
		}
	}
}

func TestCandidatesMaskKeyspace(t *testing.T) {
	s := noDefault()
	s.Patterns.Masks = []string{"?d?d"}
	a, err := NewAssembler(s, Runtime{})
	if err != nil {
		t.Fatalf("NewAssembler: %v", err)
	}
	if got := a.Keyspace("f"); got != 100 {
		t.Fatalf("mask ?d?d keyspace = %d, want 100", got)
	}
}

func TestCandidatesShardPartitionsKeyspace(t *testing.T) {
	// Two disjoint shards of a ?d?d?d mask (1000 candidates) must together cover
	// the whole keyspace with no overlap.
	base := func() *Spec {
		s := noDefault()
		s.Patterns.Masks = []string{"?d?d?d"}
		return s
	}
	seen := map[string]int{}
	total := 0
	for i := 0; i < 2; i++ {
		s := base()
		s.Search.Shard = itoshard(i, 2)
		a, err := NewAssembler(s, Runtime{})
		if err != nil {
			t.Fatalf("NewAssembler shard %d: %v", i, err)
		}
		for _, c := range drain(t, a.Candidates("f"), 2000) {
			seen[c]++
			total++
		}
	}
	if total != 1000 {
		t.Fatalf("two shards produced %d candidates, want 1000", total)
	}
	for c, n := range seen {
		if n != 1 {
			t.Fatalf("candidate %q seen %d times across shards, want exactly once", c, n)
		}
	}
}

func TestCandidatesLengthFilter(t *testing.T) {
	s := noDefault()
	s.Candidates.Passwords = []string{"a", "abc", "abcdef"}
	s.Candidates.MinLength = 2
	s.Candidates.MaxLength = 4
	a, err := NewAssembler(s, Runtime{})
	if err != nil {
		t.Fatalf("NewAssembler: %v", err)
	}
	got := drain(t, a.Candidates("f"), 100)
	if len(got) != 1 || got[0] != "abc" {
		t.Fatalf("length-filtered = %v, want [abc]", got)
	}
}

func TestNewAssemblerValidates(t *testing.T) {
	s := noDefault()
	s.Search.Shard = "9/2" // out of range
	if _, err := NewAssembler(s, Runtime{}); err == nil {
		t.Fatal("NewAssembler accepted an invalid shard")
	}
}

// itoshard renders an "i/n" shard spec.
func itoshard(i, n int) string {
	return itoa(i) + "/" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
