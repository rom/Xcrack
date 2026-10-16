package pattern

import "testing"

// applyOne compiles a single rule and applies it to in, returning the one
// output, or "" + rejected=true when the rule rejects.
func applyOne(t *testing.T, rule, in string) (string, bool) {
	t.Helper()
	rs, err := CompileRules([]string{rule})
	if err != nil {
		t.Fatalf("CompileRules(%q): %v", rule, err)
	}
	out := rs.Apply([]byte(in))
	if len(out) == 0 {
		return "", true
	}
	return string(out[0]), false
}

func TestRuleTransforms(t *testing.T) {
	cases := []struct{ rule, in, want string }{
		{":", "p@ssW0rd", "p@ssW0rd"},
		{"l", "p@ssW0rd", "p@ssw0rd"},
		{"u", "p@ssW0rd", "P@SSW0RD"},
		{"c", "p@ssW0rd", "P@ssw0rd"},
		{"C", "p@ssW0rd", "p@SSW0RD"},
		{"t", "p@ssW0rd", "P@SSw0RD"},
		{"r", "pass", "ssap"},
		{"d", "pass", "passpass"},
		{"p2", "ab", "ababab"},
		{"f", "pass", "passssap"},
		{"q", "pass", "ppaassss"},
		{"{", "pass", "assp"},
		{"}", "pass", "spas"},
		{"[", "pass", "ass"},
		{"]", "pass", "pas"},
		{"$1", "pass", "pass1"},
		{"^1", "pass", "1pass"},
		{"@s", "pass", "pa"},
		{"sa@", "pass", "p@ss"},
		{"z2", "pass", "pppass"},
		{"Z1", "pass", "passs"},
		{"y2", "pass", "papass"},
		{"Y2", "pass", "passss"},
		{"'4", "password", "pass"},
		{"x12", "password", "as"},
		{"i1X", "pass", "pXass"},
		{"o1X", "pass", "pXss"},
		{"*12", "pass", "psas"},
		{"k", "pass", "apss"},
		{"K", "word", "wodr"},
		{"+0", "az", "bz"},
		{"-0", "bz", "az"},
		{".1", "abc", "acc"},
		{",1", "abc", "aac"},
		{"e-", "foo-bar", "Foo-Bar"},
		{"T3", "p@ssw0rd", "p@sSw0rd"},
		{"D2", "pass", "pas"},
	}
	for _, c := range cases {
		got, rejected := applyOne(t, c.rule, c.in)
		if rejected {
			t.Errorf("rule %q on %q was rejected; want %q", c.rule, c.in, c.want)
			continue
		}
		if got != c.want {
			t.Errorf("rule %q on %q = %q; want %q", c.rule, c.in, got, c.want)
		}
	}
}

func TestRuleRejections(t *testing.T) {
	cases := []struct {
		rule, in string
		reject   bool
	}{
		{"<5", "pass", false}, {"<5", "passw", true},
		{">3", "pass", false}, {">3", "ab", true},
		{"_4", "pass", false}, {"_4", "pas", true},
		{"!s", "abc", false}, {"!s", "pass", true},
		{"/s", "pass", false}, {"/s", "abc", true},
		{"(p", "pass", false}, {"(p", "aass", true},
		{")s", "pass", false}, {")s", "pasx", true},
		{"=1a", "pass", false}, {"=1a", "pbss", true},
	}
	for _, c := range cases {
		_, rejected := applyOne(t, c.rule, c.in)
		if rejected != c.reject {
			t.Errorf("rule %q on %q: rejected=%v; want %v", c.rule, c.in, rejected, c.reject)
		}
	}
}

func TestRuleStacking(t *testing.T) {
	// Capitalize then append "1": "pass" -> "Pass" -> "Pass1".
	got, rejected := applyOne(t, "c $1", "pass")
	if rejected || got != "Pass1" {
		t.Fatalf("stacked rule = %q (rejected=%v); want Pass1", got, rejected)
	}
}

func TestRuleRejectDropsOutput(t *testing.T) {
	// A rule set where one rule rejects: only the surviving rule produces output.
	rs, err := CompileRules([]string{"u", ">A"}) // >A = length > 10
	if err != nil {
		t.Fatal(err)
	}
	out := rs.Apply([]byte("pass"))
	if len(out) != 1 || string(out[0]) != "PASS" {
		t.Fatalf("Apply = %q; want [PASS]", out)
	}
}
