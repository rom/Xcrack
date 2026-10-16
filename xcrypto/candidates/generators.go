package candidates

import "io"

// --- toggle-case ---

// maxToggleLetters caps the alphabetic positions a ToggleCase source permutes
// per word, so a long word cannot explode into 2^n variants.
const maxToggleLetters = 12

// ToggleCase wraps a base Source and, for each word, emits every case
// assignment of its first min(k, maxLetters) alphabetic characters (2^min(k,
// maxLetters) variants, letters beyond that and non-letters left as-is). This
// is hashcat's toggle-case attack. maxLetters <= 0 uses the default cap.
func ToggleCase(base Source, maxLetters int) Source {
	if maxLetters <= 0 || maxLetters > maxToggleLetters {
		maxLetters = maxToggleLetters
	}
	return &toggleSource{base: base, maxLetters: maxLetters}
}

type toggleSource struct {
	base       Source
	maxLetters int

	word    []byte
	letters []int  // indexes of the alphabetic positions we permute
	combo   uint32 // next case-assignment bitmask
	combos  uint32 // total assignments for the current word (1<<len(letters))
	have    bool
}

func isAlpha(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') }

func (s *toggleSource) load() error {
	for {
		w, err := s.base.Next()
		if err != nil {
			return err
		}
		s.word = append(s.word[:0], w...)
		s.letters = s.letters[:0]
		for i, c := range s.word {
			if isAlpha(c) && len(s.letters) < s.maxLetters {
				s.letters = append(s.letters, i)
			}
		}
		s.combo = 0
		s.combos = 1 << uint(len(s.letters))
		s.have = true
		return nil
	}
}

func (s *toggleSource) Next() ([]byte, error) {
	if !s.have || s.combo >= s.combos {
		if err := s.load(); err != nil {
			return nil, err
		}
	}
	out := make([]byte, len(s.word))
	copy(out, s.word)
	for bit, pos := range s.letters {
		c := out[pos]
		if s.combo&(1<<uint(bit)) != 0 {
			c &^= 0x20 // uppercase
		} else {
			c |= 0x20 // lowercase
		}
		out[pos] = c
	}
	s.combo++
	return out, nil
}

func (s *toggleSource) Len() int64 { return -1 }

func (s *toggleSource) Reset() error {
	s.have = false
	s.word = s.word[:0]
	return s.base.Reset()
}

func (s *toggleSource) CloneSource() Source {
	cl, ok := s.base.(Cloner)
	if !ok {
		return nil
	}
	b := cl.CloneSource()
	if b == nil {
		return nil
	}
	return &toggleSource{base: b, maxLetters: s.maxLetters}
}

// --- keyboard walk ---

// qwertyRows is the US-QWERTY key grid used for adjacency walks.
var qwertyRows = []string{
	"`1234567890-=",
	"qwertyuiop[]\\",
	"asdfghjkl;'",
	"zxcvbnm,./",
}

// walkDirs are the eight grid directions (row,col deltas) a straight keyboard
// walk can follow: right/left/down/up and the four diagonals.
var walkDirs = [8][2]int{{0, 1}, {0, -1}, {1, 0}, {-1, 0}, {1, 1}, {1, -1}, {-1, 1}, {-1, -1}}

// KeyboardWalk generates straight-line adjacency walks on a US-QWERTY keyboard
// (hashcat/kwprocessor style): from every key, in each of the eight directions,
// it follows adjacent keys and emits every prefix whose length is in
// [minLen, maxLen] — so "qwer", "qwerty", "asdfg", "zxcv", "1wsx", "zse4" all
// appear. This is a small, high-signal set (the walks people actually type),
// deduplicated and bounded by max, not the full combinatorial adjacency tree.
func KeyboardWalk(minLen, maxLen, max int) Source {
	if minLen < 1 {
		minLen = 1
	}
	if maxLen < minLen {
		maxLen = minLen
	}
	if max <= 0 {
		max = 1 << 16
	}
	var out [][]byte
	seen := make(map[string]struct{}, max)
	emit := func(w []byte) {
		if len(w) < minLen {
			return
		}
		if _, dup := seen[string(w)]; dup {
			return
		}
		seen[string(w)] = struct{}{}
		out = append(out, append([]byte(nil), w...))
	}
	for r0 := range qwertyRows {
		for c0 := 0; c0 < len(qwertyRows[r0]) && len(out) < max; c0++ {
			for _, d := range walkDirs {
				if len(out) >= max {
					break
				}
				var w []byte
				r, c := r0, c0
				for len(w) < maxLen {
					if r < 0 || r >= len(qwertyRows) {
						break
					}
					row := qwertyRows[r]
					if c < 0 || c >= len(row) {
						break
					}
					w = append(w, row[c])
					emit(w) // every prefix >= minLen
					r += d[0]
					c += d[1]
				}
			}
		}
	}
	return &sliceSource{items: out}
}

// --- PRINCE ---

// Prince emits concatenations of 1..maxWords words drawn from the word source
// (hashcat's PRINCE attack), keeping only those whose total length is in
// [minLen, maxLen], up to max candidates. Shorter chains are emitted before
// longer ones. The word source is drained (bounded) and the product generated
// lazily.
func Prince(words Source, minLen, maxLen, maxWords, max int) Source {
	if maxWords < 1 {
		maxWords = 2
	}
	if minLen < 1 {
		minLen = 1
	}
	if maxLen < minLen {
		maxLen = minLen
	}
	if max <= 0 {
		max = 1 << 20
	}
	w := drainTo(words, maxComboInput)
	return &princeSource{words: w, minLen: minLen, maxLen: maxLen, maxWords: maxWords, max: max, n: 1}
}

type princeSource struct {
	words          [][]byte
	minLen, maxLen int
	maxWords, max  int
	n              int   // current chain length (number of words)
	idx            []int // odometer over word indices, len == n
	emitted        int
	done           bool
}

func (p *princeSource) Next() ([]byte, error) {
	if p.done || len(p.words) == 0 || p.emitted >= p.max {
		return nil, io.EOF
	}
	if p.idx == nil {
		p.idx = make([]int, p.n)
	}
	for {
		// Build the current concatenation and measure it.
		total := 0
		for _, i := range p.idx {
			total += len(p.words[i])
		}
		var out []byte
		emit := total >= p.minLen && total <= p.maxLen
		if emit {
			out = make([]byte, 0, total)
			for _, i := range p.idx {
				out = append(out, p.words[i]...)
			}
		}
		// Advance the odometer (rightmost fastest); roll to the next chain length
		// when it overflows.
		k := p.n - 1
		for ; k >= 0; k-- {
			p.idx[k]++
			if p.idx[k] < len(p.words) {
				break
			}
			p.idx[k] = 0
		}
		if k < 0 {
			p.n++
			if p.n > p.maxWords || p.n > p.maxLen {
				p.done = true
			} else {
				p.idx = make([]int, p.n)
			}
		}
		if emit {
			p.emitted++
			return out, nil
		}
		if p.done || p.emitted >= p.max {
			return nil, io.EOF
		}
	}
}

func (p *princeSource) Len() int64 { return -1 }

func (p *princeSource) Reset() error {
	p.n, p.idx, p.emitted, p.done = 1, nil, 0, false
	return nil
}

func (p *princeSource) CloneSource() Source {
	return &princeSource{words: p.words, minLen: p.minLen, maxLen: p.maxLen, maxWords: p.maxWords, max: p.max, n: 1}
}
