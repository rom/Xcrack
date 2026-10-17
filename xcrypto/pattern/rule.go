package pattern

import (
	"fmt"
	"io"

	"github.com/rom/xcrypto/candidates"
)

// A ruleOp transforms a word, returning the new word and whether to keep it.
// A reject rule returns keep=false, which drops the whole rule's output.
type ruleOp func([]byte) ([]byte, bool)

// Rule is a compiled sequence of mangling operations.
type Rule struct {
	ops []ruleOp
	src string
}

// RuleSet is an ordered list of rules. Applying it to a word yields one
// candidate per rule that is not rejected, in order.
type RuleSet struct {
	rules []Rule
}

// CompileRules compiles a hashcat-style rule per non-empty, non-comment line.
//
// Supported functions:
//
//	Nop/case:  : l u c C t TN
//	Reverse/dup: r d pN f q zN ZN yN YN
//	Rotate/trim: { } [ ] 'N xNM
//	Edit:       $X ^X @X sXY iNX oNX *NM k K DN +N -N .N ,N LN RN eX
//	Reject:     <N >N _N !X /X (X )X =NX
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
	i := 0
	arg := func() (byte, bool) {
		if i+1 < len(b) {
			i++
			return b[i], true
		}
		return 0, false
	}
	need := func(c byte, n int) error { return fmt.Errorf("'%c' needs %d argument(s)", c, n) }
	for ; i < len(b); i++ {
		c := b[i]
		if c == ' ' || c == '\t' {
			continue
		}
		switch c {
		case ':':
			// nop
		case 'l':
			r.ops = append(r.ops, opMap(toLower))
		case 'u':
			r.ops = append(r.ops, opMap(toUpper))
		case 'c':
			r.ops = append(r.ops, opKeep(opCapitalize))
		case 'C':
			r.ops = append(r.ops, opKeep(opInvCapitalize))
		case 't':
			r.ops = append(r.ops, opMap(toggle))
		case 'r':
			r.ops = append(r.ops, opKeep(opReverse))
		case 'd':
			r.ops = append(r.ops, opKeep(opDuplicate))
		case 'f':
			r.ops = append(r.ops, opKeep(opReflect))
		case 'q':
			r.ops = append(r.ops, opKeep(opDupEachChar))
		case '{':
			r.ops = append(r.ops, opKeep(opRotLeft))
		case '}':
			r.ops = append(r.ops, opKeep(opRotRight))
		case '[':
			r.ops = append(r.ops, opKeep(opDelFirst))
		case ']':
			r.ops = append(r.ops, opKeep(opDelLast))
		case 'k':
			r.ops = append(r.ops, opKeep(opSwapFront))
		case 'K':
			r.ops = append(r.ops, opKeep(opSwapBack))
		case '$':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opAppend(x)))
		case '^':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opPrepend(x)))
		case '@':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opPurge(x)))
		case 's':
			x, ok1 := arg()
			y, ok2 := arg()
			if !ok1 || !ok2 {
				return r, need(c, 2)
			}
			r.ops = append(r.ops, opKeep(opSub(x, y)))
		case 'e':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opTitleSep(x)))
		case 'T':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opAt(decodePos(p), toggleByte)))
		case 'D':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opDeleteAt(decodePos(p))))
		case 'p':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opDupWordN(decodePos(p))))
		case 'z':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opDupFirstN(decodePos(p))))
		case 'Z':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opDupLastN(decodePos(p))))
		case 'y':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opDupBlockFront(decodePos(p))))
		case 'Y':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opDupBlockBack(decodePos(p))))
		case '\'':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opTruncate(decodePos(p))))
		case 'x':
			n, ok1 := arg()
			m, ok2 := arg()
			if !ok1 || !ok2 {
				return r, need(c, 2)
			}
			r.ops = append(r.ops, opKeep(opExtract(decodePos(n), decodePos(m))))
		case 'i':
			n, ok1 := arg()
			x, ok2 := arg()
			if !ok1 || !ok2 {
				return r, need(c, 2)
			}
			r.ops = append(r.ops, opKeep(opInsert(decodePos(n), x)))
		case 'o':
			n, ok1 := arg()
			x, ok2 := arg()
			if !ok1 || !ok2 {
				return r, need(c, 2)
			}
			r.ops = append(r.ops, opKeep(opAt(decodePos(n), func(byte) byte { return x })))
		case '*':
			n, ok1 := arg()
			m, ok2 := arg()
			if !ok1 || !ok2 {
				return r, need(c, 2)
			}
			r.ops = append(r.ops, opKeep(opSwap(decodePos(n), decodePos(m))))
		case '+':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opAt(decodePos(p), func(b byte) byte { return b + 1 })))
		case '-':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opAt(decodePos(p), func(b byte) byte { return b - 1 })))
		case 'L':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opAt(decodePos(p), func(b byte) byte { return b << 1 })))
		case 'R':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opAt(decodePos(p), func(b byte) byte { return b >> 1 })))
		case '.':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opReplaceWithNeighbor(decodePos(p), +1)))
		case ',':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, opKeep(opReplaceWithNeighbor(decodePos(p), -1)))
		// --- rejection rules ---
		case '<':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			n := decodePos(p)
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, len(w) < n })
		case '>':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			n := decodePos(p)
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, len(w) > n })
		case '_':
			p, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			n := decodePos(p)
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, len(w) == n })
		case '!':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, !contains(w, x) })
		case '/':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, contains(w, x) })
		case '(':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, len(w) > 0 && w[0] == x })
		case ')':
			x, ok := arg()
			if !ok {
				return r, need(c, 1)
			}
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, len(w) > 0 && w[len(w)-1] == x })
		case '=':
			n, ok1 := arg()
			x, ok2 := arg()
			if !ok1 || !ok2 {
				return r, need(c, 2)
			}
			pos := decodePos(n)
			r.ops = append(r.ops, func(w []byte) ([]byte, bool) { return w, pos >= 0 && pos < len(w) && w[pos] == x })
		default:
			return r, fmt.Errorf("unsupported rule function %q", string(c))
		}
	}
	return r, nil
}

// maxRuleWordLen caps a mangled word's length (matching hashcat's password
// cap). Duplication functions (d, p, f, z, …) can otherwise be chained to grow a
// word exponentially; the word is truncated to this length after each op so rule
// application stays memory-bounded on hostile rule input.
const maxRuleWordLen = 256

// Len reports the number of compiled rules.
func (rs *RuleSet) Len() int { return len(rs.rules) }

// Apply returns the word as transformed by each rule, one output per rule that
// is not rejected, in order.
func (rs *RuleSet) Apply(word []byte) [][]byte {
	out := make([][]byte, 0, len(rs.rules))
	for _, r := range rs.rules {
		w := append([]byte(nil), word...)
		if len(w) > maxRuleWordLen {
			w = w[:maxRuleWordLen]
		}
		keep := true
		for _, op := range r.ops {
			var ok bool
			w, ok = op(w)
			if !ok {
				keep = false
				break
			}
			if len(w) > maxRuleWordLen {
				w = w[:maxRuleWordLen]
			}
		}
		if keep {
			out = append(out, w)
		}
	}
	return out
}

// RuleDebug is the outcome of applying one rule to one word, for rule-file
// debugging (hashcat's --debug-mode): the rule source, its transformed output,
// and whether the rule kept or rejected the word.
type RuleDebug struct {
	Rule   string
	Output []byte // valid only when Kept
	Kept   bool
}

// ApplyDebug is Apply with per-rule accounting: one RuleDebug per rule, in
// order, recording the transformed output or that the rule rejected the word.
func (rs *RuleSet) ApplyDebug(word []byte) []RuleDebug {
	out := make([]RuleDebug, 0, len(rs.rules))
	for _, r := range rs.rules {
		w := append([]byte(nil), word...)
		if len(w) > maxRuleWordLen {
			w = w[:maxRuleWordLen]
		}
		keep := true
		for _, op := range r.ops {
			var ok bool
			w, ok = op(w)
			if !ok {
				keep = false
				break
			}
			if len(w) > maxRuleWordLen {
				w = w[:maxRuleWordLen]
			}
		}
		rd := RuleDebug{Rule: r.src, Kept: keep}
		if keep {
			rd.Output = w
		}
		out = append(out, rd)
	}
	return out
}

// RuleLines returns the rule source lines in order.
func (rs *RuleSet) RuleLines() []string {
	out := make([]string, len(rs.rules))
	for i, r := range rs.rules {
		out[i] = r.src
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

func (s *ruleSource) Len() int64 { return -1 } // rejects make the count non-trivial

func (s *ruleSource) Reset() error {
	s.queue = nil
	return s.base.Reset()
}

var _ = io.EOF // ruleSource surfaces base's io.EOF via Next

// --- op implementations ---

// opKeep lifts a never-rejecting transform into a ruleOp.
func opKeep(f func([]byte) []byte) ruleOp {
	return func(w []byte) ([]byte, bool) { return f(w), true }
}

func opMap(f func(byte) byte) ruleOp {
	return func(w []byte) ([]byte, bool) {
		for i := range w {
			w[i] = f(w[i])
		}
		return w, true
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
func toggle(b byte) byte { return toggleByte(b) }
func toggleByte(b byte) byte {
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
func opTitleSep(sep byte) func([]byte) []byte {
	return func(w []byte) []byte {
		upNext := true
		for i := range w {
			if upNext {
				w[i] = toUpper(w[i])
			} else {
				w[i] = toLower(w[i])
			}
			upNext = w[i] == sep
		}
		return w
	}
}
func opReverse(w []byte) []byte {
	for i, j := 0, len(w)-1; i < j; i, j = i+1, j-1 {
		w[i], w[j] = w[j], w[i]
	}
	return w
}
func opDuplicate(w []byte) []byte { return append(w, w...) }
func opDupEachChar(w []byte) []byte {
	out := make([]byte, 0, len(w)*2)
	for _, b := range w {
		out = append(out, b, b)
	}
	return out
}
func opReflect(w []byte) []byte {
	r := append([]byte(nil), w...)
	opReverse(r)
	return append(w, r...)
}
func opDupWordN(n int) func([]byte) []byte {
	return func(w []byte) []byte {
		orig := append([]byte(nil), w...)
		for k := 0; k < n; k++ {
			w = append(w, orig...)
		}
		return w
	}
}
func opDupFirstN(n int) func([]byte) []byte {
	return func(w []byte) []byte {
		if len(w) == 0 || n <= 0 {
			return w
		}
		pre := make([]byte, n)
		for i := range pre {
			pre[i] = w[0]
		}
		return append(pre, w...)
	}
}
func opDupLastN(n int) func([]byte) []byte {
	return func(w []byte) []byte {
		if len(w) == 0 {
			return w
		}
		for k := 0; k < n; k++ {
			w = append(w, w[len(w)-1])
		}
		return w
	}
}
func opDupBlockFront(n int) func([]byte) []byte {
	return func(w []byte) []byte {
		k := n
		if k <= 0 {
			return w
		}
		if k > len(w) {
			k = len(w)
		}
		pre := append([]byte(nil), w[:k]...)
		return append(pre, w...)
	}
}
func opDupBlockBack(n int) func([]byte) []byte {
	return func(w []byte) []byte {
		k := n
		if k <= 0 {
			return w
		}
		if k > len(w) {
			k = len(w)
		}
		return append(w, w[len(w)-k:]...)
	}
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
func opSwapFront(w []byte) []byte {
	if len(w) >= 2 {
		w[0], w[1] = w[1], w[0]
	}
	return w
}
func opSwapBack(w []byte) []byte {
	if n := len(w); n >= 2 {
		w[n-1], w[n-2] = w[n-2], w[n-1]
	}
	return w
}
func opTruncate(n int) func([]byte) []byte {
	return func(w []byte) []byte {
		if n >= 0 && n < len(w) {
			return w[:n]
		}
		return w
	}
}
func opExtract(n, m int) func([]byte) []byte {
	return func(w []byte) []byte {
		if n < 0 || m < 0 || n+m > len(w) {
			return w
		}
		return append([]byte(nil), w[n:n+m]...)
	}
}
func opInsert(n int, x byte) func([]byte) []byte {
	return func(w []byte) []byte {
		if n < 0 || n > len(w) {
			return w
		}
		out := make([]byte, 0, len(w)+1)
		out = append(out, w[:n]...)
		out = append(out, x)
		out = append(out, w[n:]...)
		return out
	}
}
func opSwap(n, m int) func([]byte) []byte {
	return func(w []byte) []byte {
		if n >= 0 && m >= 0 && n < len(w) && m < len(w) {
			w[n], w[m] = w[m], w[n]
		}
		return w
	}
}
func opReplaceWithNeighbor(n, delta int) func([]byte) []byte {
	return func(w []byte) []byte {
		j := n + delta
		if n >= 0 && n < len(w) && j >= 0 && j < len(w) {
			w[n] = w[j]
		}
		return w
	}
}
func opAppend(x byte) func([]byte) []byte { return func(w []byte) []byte { return append(w, x) } }
func opPrepend(x byte) func([]byte) []byte {
	return func(w []byte) []byte { return append([]byte{x}, w...) }
}
func opPurge(x byte) func([]byte) []byte {
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
func opSub(x, y byte) func([]byte) []byte {
	return func(w []byte) []byte {
		for i := range w {
			if w[i] == x {
				w[i] = y
			}
		}
		return w
	}
}
func opAt(n int, f func(byte) byte) func([]byte) []byte {
	return func(w []byte) []byte {
		if n >= 0 && n < len(w) {
			w[n] = f(w[n])
		}
		return w
	}
}
func opDeleteAt(n int) func([]byte) []byte {
	return func(w []byte) []byte {
		if n >= 0 && n < len(w) {
			return append(w[:n], w[n+1:]...)
		}
		return w
	}
}

func contains(w []byte, x byte) bool {
	for _, b := range w {
		if b == x {
			return true
		}
	}
	return false
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
