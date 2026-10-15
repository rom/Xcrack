package pattern

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"

	"github.com/rom/xcrypto/candidates"
)

// Spec is a declarative pattern description. Both the pattern-file DSL
// (ParseText) and a caller's YAML wrapper produce one.
type Spec struct {
	Masks          []string
	Rules          []string
	CustomCharsets map[rune]string
}

// Set is a compiled Spec: zero or more masks and an optional rule set.
type Set struct {
	masks []*Mask
	rules *RuleSet
}

// Compile compiles a Spec.
func Compile(s Spec) (*Set, error) {
	set := &Set{}
	for _, m := range s.Masks {
		cm, err := CompileMask(m, s.CustomCharsets)
		if err != nil {
			return nil, err
		}
		set.masks = append(set.masks, cm)
	}
	if len(s.Rules) > 0 {
		rs, err := CompileRules(s.Rules)
		if err != nil {
			return nil, err
		}
		set.rules = rs
	}
	return set, nil
}

// Empty reports whether the set has neither masks nor rules.
func (s *Set) Empty() bool { return len(s.masks) == 0 && s.rules == nil }

// HasRules reports whether the set carries mangling rules.
func (s *Set) HasRules() bool { return s.rules != nil }

// MaskSources returns one candidate source per mask.
func (s *Set) MaskSources() []candidates.Source {
	out := make([]candidates.Source, 0, len(s.masks))
	for _, m := range s.masks {
		out = append(out, m.Source())
	}
	return out
}

// ApplyRules wraps base with the rule set (returns base unchanged if there are
// no rules).
func (s *Set) ApplyRules(base candidates.Source) candidates.Source {
	if s.rules == nil {
		return base
	}
	return WithRules(base, s.rules)
}

// Keyspace returns the total mask keyspace (sum across masks), or -1 if unknown
// or overflowing.
func (s *Set) Keyspace() int64 {
	var total int64
	for _, m := range s.masks {
		k := m.Keyspace()
		if k < 0 {
			return -1
		}
		total += k
	}
	return total
}

// ParseText parses the Xcrack pattern-file DSL into a Spec. Lines:
//
//	# comment
//	mask: ?u?l?l?l?d?d        (or "mask ?u?l?l?l?d?d")
//	rule: c $1                (or "rule c $1")
//	charset1: abcdef0123456789 (charset1..charset4 define ?1..?4)
//
// A bare line with no recognized prefix is treated as a mask for convenience.
func ParseText(data []byte) (Spec, error) {
	spec := Spec{CustomCharsets: map[rune]string{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	ln := 0
	for sc.Scan() {
		ln++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val := splitDirective(line)
		switch key {
		case "mask":
			spec.Masks = append(spec.Masks, val)
		case "rule":
			spec.Rules = append(spec.Rules, val)
		case "charset1", "charset2", "charset3", "charset4":
			spec.CustomCharsets[rune('0'+key[len(key)-1]-'0')] = val
		case "":
			spec.Masks = append(spec.Masks, val) // bare line => mask
		default:
			return spec, fmt.Errorf("pattern: line %d: unknown directive %q", ln, key)
		}
	}
	if err := sc.Err(); err != nil {
		return spec, err
	}
	return spec, nil
}

func splitDirective(line string) (key, val string) {
	for _, sep := range []string{":", " ", "\t"} {
		if i := strings.Index(line, sep); i > 0 {
			k := strings.TrimSpace(line[:i])
			switch k {
			case "mask", "rule", "charset1", "charset2", "charset3", "charset4":
				return k, strings.TrimSpace(line[i+1:])
			}
		}
	}
	return "", line
}
