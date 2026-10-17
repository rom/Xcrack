package pattern

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseHCMaskLine(t *testing.T) {
	cases := []struct {
		line       string
		wantSpec   string
		wantCustom map[rune]string
		wantErr    bool
	}{
		{"?l?l?d?d", "?l?l?d?d", map[rune]string{}, false},
		{"abcdef,?1?1?1", "?1?1?1", map[rune]string{'1': "abcdef"}, false},
		{"abc,123,?1?2?1", "?1?2?1", map[rune]string{'1': "abc", '2': "123"}, false},
		{`a\,b,?1?1`, "?1?1", map[rune]string{'1': "a,b"}, false}, // escaped comma in charset
		{"a,b,c,d,e,?1", "", nil, true},                           // >4 custom charsets
		{"a,,?1?2", "", nil, true},                                // empty custom charset
	}
	for _, c := range cases {
		spec, custom, err := ParseHCMaskLine(c.line, nil)
		if c.wantErr {
			if err == nil {
				t.Errorf("%q: want error", c.line)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", c.line, err)
			continue
		}
		if spec != c.wantSpec {
			t.Errorf("%q: spec = %q, want %q", c.line, spec, c.wantSpec)
		}
		for k, v := range c.wantCustom {
			if custom[k] != v {
				t.Errorf("%q: custom[%c] = %q, want %q", c.line, k, custom[k], v)
			}
		}
	}
}

func TestLoadHCMask(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rockyou-1-60.hcmask")
	content := "# a sample hcmask file\n" +
		"?l?l?l?l?d?d\n" +
		"\n" +
		"abc123,?1?1?1?1\n" +
		"?u?l?l?l?l?l?d\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	masks, err := LoadHCMask(path, nil)
	if err != nil {
		t.Fatalf("LoadHCMask: %v", err)
	}
	if len(masks) != 3 {
		t.Fatalf("got %d masks, want 3 (comments/blanks skipped)", len(masks))
	}
	// The custom-charset mask ?1?1?1?1 over "abc123" (6 symbols) = 6^4 keyspace.
	if ks := masks[1].Keyspace(); ks != 6*6*6*6 {
		t.Errorf("custom-charset mask keyspace = %d, want %d", ks, 6*6*6*6)
	}
	// A malformed file (undefined custom charset) errors with a line number.
	bad := filepath.Join(dir, "bad.hcmask")
	os.WriteFile(bad, []byte("?1?1\n"), 0o600)
	if _, err := LoadHCMask(bad, nil); err == nil {
		t.Error("expected error for a mask using an undefined custom charset")
	}
}

// TestParseTextIdentityRule guards against a split bug where "rule :" (the
// identity rule) was mis-split at its own colon and dropped. Both the
// colon-after-key and space-before-value forms must preserve the rule value.
func TestParseTextIdentityRule(t *testing.T) {
	spec, err := ParseText([]byte("rule :\nrule $1\nrule: c\nmask ?d?d\n"))
	if err != nil {
		t.Fatal(err)
	}
	wantRules := []string{":", "$1", "c"}
	if len(spec.Rules) != len(wantRules) {
		t.Fatalf("rules = %q, want %q", spec.Rules, wantRules)
	}
	for i, w := range wantRules {
		if spec.Rules[i] != w {
			t.Errorf("rule[%d] = %q, want %q", i, spec.Rules[i], w)
		}
	}
	if len(spec.Masks) != 1 || spec.Masks[0] != "?d?d" {
		t.Errorf("masks = %q, want [?d?d]", spec.Masks)
	}
	// The identity rule must compile and pass a word through unchanged.
	set, err := Compile(spec)
	if err != nil {
		t.Fatal(err)
	}
	got := set.Rules().ApplyDebug([]byte("cat"))
	if len(got) == 0 || !got[0].Kept || string(got[0].Output) != "cat" {
		t.Fatalf("identity rule did not pass %q through: %+v", "cat", got[0])
	}
}
