package pattern

import (
	"strings"
	"testing"
)

// The invariant for every fuzz target here: no panic, bounded work, terminates.

func FuzzCompileMask(f *testing.F) {
	for _, s := range []string{"?l?u?d?s?a?b", "?1?2?3?4", "abc?d", "??", "?", "", "x?lx", "?z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		m, err := CompileMask(spec, map[rune]string{'1': "ab", '2': "xy", '3': "0", '4': "!"})
		if err != nil || m == nil {
			return
		}
		_ = m.Keyspace()
		s := m.Source()
		for i := 0; i < 2000; i++ { // bound enumeration
			if _, e := s.Next(); e != nil {
				break
			}
		}
	})
}

func FuzzCompileRules(f *testing.F) {
	for _, s := range []string{":\nc\nu\nl\n$1\n^x\nsab\n@z\nT0\nD1\nr\nd\nf\n{\n}\n[\n]", "C t", "$", "s", "T", "", "#comment\nc"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, lines string) {
		rs, err := CompileRules(strings.Split(lines, "\n"))
		if err != nil || rs == nil {
			return
		}
		rs.Apply([]byte("Passw0rd!"))
		rs.Apply(nil)
	})
}

func FuzzParseText(f *testing.F) {
	for _, s := range []string{"mask: ?d?d\nrule: c\ncharset1: abc", "# c\n?l?l", "charset9: x", "random line", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		spec, err := ParseText([]byte(s))
		if err != nil {
			return
		}
		if set, err := Compile(spec); err == nil && set != nil {
			_ = set.Keyspace()
		}
	})
}
