package pattern

import (
	"fmt"
	"io"

	"github.com/rom/xcrypto/candidates"
)

// A ruleOp transforms a word in place-ish, returning the new word.
type ruleOp func([]byte) []byte

// Rule is a compiled sequence of mangling operations.
type Rule struct {
	ops []ruleOp
	src string
}

// RuleSet is an ordered list of rules. Applying it to a word yields one
// candidate per rule, in order.
type RuleSet struct {
	rules []Rule
}

// CompileRules compiles a hashcat-style rule per non-empty, non-comment line.
// Supported functions (a practical subset): : l u c C t TN r d f { } $X ^X sXY
// @X [ ] DN.
func CompileRules(lines []string) (*RuleSet, error) {
	rs := &RuleSet{}
	for n, line := range lines {
		if line == "" || line[0] == '#' {
			continue
		}
		r, err := compileRule(line)
		if err != nil {
			return nil, fmt.Errorf("pattern: rule line %d (%q): %w", n+1, line, err)
		}
		rs.rules = append(rs.rules, r)
	}
	return rs, nil
}

func compileRule(line string) (Rule, error) {
	r := Rule{src: line}
	b := []byte(line)
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c == ' ' || c == '\t' {
			continue
		}
		arg := func() (byte, bool) {
			if i+1 < len(b) {
				i++
				return b[i], true
			}
			return 0, false
		}
		switch c {
		case ':':
			// nop
		case 'l':
			r.ops = append(r.ops, opMap(toLower))
		case 'u':
			r.ops = append(r.ops, opMap(toUpper))
		case 'c':
			r.ops = append(r.ops, opCapitalize)
		case 'C':
			r.ops = append(r.ops, opInvCapitalize)
		case 't':
			r.ops = append(r.ops, opMap(toggle))
		case 'r':
			r.ops = append(r.ops, opReverse)
		case 'd':
			r.ops = append(r.ops, opDuplicate)
		case 'f':
			r.ops = append(r.ops, opReflect)
		case '{':
			r.ops = append(r.ops, opRotLeft)
		case '}':
			r.ops = append(r.ops, opRotRight)
		case '[':
			r.ops = append(r.ops, opDelFirst)
		case ']':
			r.ops = append(r.ops, opDelLast)
		case '$':
			x, ok := arg()
			if !ok {
				return r, fmt.Errorf("'$' needs a char")
			}
			r.ops = append(r.ops, opAppend(x))
		case '^':
			x, ok := arg()
			if !ok {
				return r, fmt.Errorf("'^' needs a char")
			}
			r.ops = append(r.ops, opPrepend(x))
		case '@':
			x, ok := arg()
			if !ok {
				return r, fmt.Errorf("'@' needs a char")
			}
			r.ops = append(r.ops, opPurge(x))
		case 's':
			x, ok1 := arg()
			y, ok2 := arg()
			if !ok1 || !ok2 {
				return r, fmt.Errorf("'s' needs two chars")
			}
			r.ops = append(r.ops, opSub(x, y))
		case 'T':
			p, ok := arg()
			if !ok {
				return r, fmt.Errorf("'T' needs a position")
			}
			r.ops = append(r.ops, opToggleAt(decodePos(p)))
		case 'D':
			p, ok := arg()
			if !ok {
				return r, fmt.Errorf("'D' needs a position")
			}
			r.ops = append(r.ops, opDeleteAt(decodePos(p)))
		default:
			return r, fmt.Errorf("unsupported rule function %q", string(c))
		}
	}
	return r, nil
}

// Apply returns the word as transformed by each rule, one output per rule.
func (rs *RuleSet) Apply(word []byte) [][]byte {
	out := make([][]byte, 0, len(rs.rules))
	for _, r := range rs.rules {
		w := append([]byte(nil), word...)
		for _, op := range r.ops {
			w = op(w)
		}
		out = append(out, w)
	}
	return out
}

// WithRules wraps a base source so every base word is expanded into its
// rule-mangled variants.
func WithRules(base candidates.Source, rs *RuleSet) candidates.Source {
	return &ruleSource{base: base, rs: rs}
}

type ruleSource struct {
	base  candidates.Source
	rs    *RuleSet
	queue [][]byte
}

func (s *ruleSource) Next() ([]byte, error) {
	for len(s.queue) == 0 {
		w, err := s.base.Next()
		if err != nil {
			return nil, err
		}
		s.queue = s.rs.Apply(w)
	}
	v := s.queue[0]
	s.queue = s.queue[1:]
	return v, nil
}

func (s *ruleSource) Len() int64 {
	bl := s.base.Len()
	if bl < 0 {
		return -1
	}
	return bl * int64(len(s.rs.rules))
}

func (s *ruleSource) Reset() error {
	s.queue = nil
	return s.base.Reset()
}

var _ = io.EOF // ruleSource surfaces base's io.EOF via Next

// --- op implementations ---

func opMap(f func(byte) byte) ruleOp {
	return func(w []byte) []byte {
		for i := range w {
			w[i] = f(w[i])
		}
		return w
	}
}
func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}
func toUpper(b byte) byte {
	if b >= 'a' && b <= 'z' {
		return b - 32
	}
	return b
}
func toggle(b byte) byte {
	switch {
	case b >= 'a' && b <= 'z':
		return b - 32
	case b >= 'A' && b <= 'Z':
		return b + 32
	}
	return b
}
func opCapitalize(w []byte) []byte {
	for i := range w {
		if i == 0 {
			w[i] = toUpper(w[i])
		} else {
			w[i] = toLower(w[i])
		}
	}
	return w
}
func opInvCapitalize(w []byte) []byte {
	for i := range w {
		if i == 0 {
			w[i] = toLower(w[i])
		} else {
			w[i] = toUpper(w[i])
		}
	}
	return w
}
func opReverse(w []byte) []byte {
	for i, j := 0, len(w)-1; i < j; i, j = i+1, j-1 {
		w[i], w[j] = w[j], w[i]
	}
	return w
}
func opDuplicate(w []byte) []byte { return append(w, w...) }
func opReflect(w []byte) []byte {
	r := append([]byte(nil), w...)
	opReverse(r)
	return append(w, r...)
}
func opRotLeft(w []byte) []byte {
	if len(w) < 2 {
		return w
	}
	return append(w[1:], w[0])
}
func opRotRight(w []byte) []byte {
	if len(w) < 2 {
		return w
	}
	return append([]byte{w[len(w)-1]}, w[:len(w)-1]...)
}
func opDelFirst(w []byte) []byte {
	if len(w) == 0 {
		return w
	}
	return w[1:]
}
func opDelLast(w []byte) []byte {
	if len(w) == 0 {
		return w
	}
	return w[:len(w)-1]
}
func opAppend(x byte) ruleOp  { return func(w []byte) []byte { return append(w, x) } }
func opPrepend(x byte) ruleOp { return func(w []byte) []byte { return append([]byte{x}, w...) } }
func opPurge(x byte) ruleOp {
	return func(w []byte) []byte {
		out := w[:0]
		for _, b := range w {
			if b != x {
				out = append(out, b)
			}
		}
		return out
	}
}
func opSub(x, y byte) ruleOp {
	return func(w []byte) []byte {
		for i := range w {
			if w[i] == x {
				w[i] = y
			}
		}
		return w
	}
}
func opToggleAt(n int) ruleOp {
	return func(w []byte) []byte {
		if n >= 0 && n < len(w) {
			w[n] = toggle(w[n])
		}
		return w
	}
}
func opDeleteAt(n int) ruleOp {
	return func(w []byte) []byte {
		if n >= 0 && n < len(w) {
			return append(w[:n], w[n+1:]...)
		}
		return w
	}
}

// decodePos decodes a hashcat position char: '0'-'9' => 0-9, 'A'-'Z' => 10-35.
func decodePos(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 10
	}
	return -1
}
