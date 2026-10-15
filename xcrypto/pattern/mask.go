// Package pattern provides hashcat-compatible password candidate generation:
// positional charset masks (?l ?u ?d ?s ?a ?b and custom ?1-?4) and mangling
// rules applied to wordlist entries. Everything compiles to the shared
// candidates.Source interface, so masks and rules plug straight into the attack
// engine. The package is dependency-free; a readable text/YAML wrapper lives in
// the caller (e.g. the CLI).
package pattern

import (
	"fmt"
	"io"

	"github.com/rom/xcrypto/candidates"
)

// Built-in charsets.
const (
	charsLower   = "abcdefghijklmnopqrstuvwxyz"
	charsUpper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsDigit   = "0123456789"
	charsSpecial = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
)

// Mask is a compiled positional-charset template.
type Mask struct {
	pos [][]byte
}

// CompileMask compiles a hashcat-style mask. custom maps '1'..'4' to a charset
// string for ?1..?4. Literal characters are taken verbatim; "?" is escaped as
// "??".
func CompileMask(spec string, custom map[rune]string) (*Mask, error) {
	builtins := map[byte][]byte{
		'l': []byte(charsLower),
		'u': []byte(charsUpper),
		'd': []byte(charsDigit),
		's': []byte(charsSpecial),
		'a': []byte(charsLower + charsUpper + charsDigit + charsSpecial),
		'b': allBytes(),
	}
	var pos [][]byte
	b := []byte(spec)
	for i := 0; i < len(b); i++ {
		if b[i] != '?' {
			pos = append(pos, []byte{b[i]})
			continue
		}
		i++
		if i >= len(b) {
			return nil, fmt.Errorf("pattern: dangling '?' in mask %q", spec)
		}
		tok := b[i]
		switch {
		case tok == '?':
			pos = append(pos, []byte{'?'})
		case tok >= '1' && tok <= '4':
			cs, ok := custom[rune(tok)]
			if !ok || cs == "" {
				return nil, fmt.Errorf("pattern: mask uses ?%c but custom charset %c is not defined", tok, tok)
			}
			pos = append(pos, []byte(cs))
		default:
			cs, ok := builtins[tok]
			if !ok {
				return nil, fmt.Errorf("pattern: unknown mask token ?%c", tok)
			}
			pos = append(pos, cs)
		}
	}
	return &Mask{pos: pos}, nil
}

func allBytes() []byte {
	out := make([]byte, 256)
	for i := range out {
		out[i] = byte(i)
	}
	return out
}

// Keyspace returns the number of candidates the mask generates, or -1 if it
// overflows int64.
func (m *Mask) Keyspace() int64 {
	var total int64 = 1
	for _, p := range m.pos {
		if len(p) == 0 {
			return 0
		}
		next := total * int64(len(p))
		if next/int64(len(p)) != total { // overflow
			return -1
		}
		total = next
	}
	return total
}

// Source returns a candidates.Source that enumerates the mask keyspace with the
// rightmost position varying fastest.
func (m *Mask) Source() candidates.Source {
	return &maskSource{m: m, idx: make([]int, len(m.pos))}
}

type maskSource struct {
	m    *Mask
	idx  []int
	done bool
}

func (s *maskSource) Next() ([]byte, error) {
	if s.done {
		return nil, io.EOF
	}
	out := make([]byte, len(s.m.pos))
	for i, p := range s.m.pos {
		out[i] = p[s.idx[i]]
	}
	// odometer increment, rightmost fastest
	i := len(s.idx) - 1
	for ; i >= 0; i-- {
		s.idx[i]++
		if s.idx[i] < len(s.m.pos[i]) {
			break
		}
		s.idx[i] = 0
	}
	if i < 0 {
		s.done = true
	}
	return out, nil
}

func (s *maskSource) Len() int64 { return s.m.Keyspace() }

func (s *maskSource) Reset() error {
	for i := range s.idx {
		s.idx[i] = 0
	}
	s.done = false
	return nil
}
