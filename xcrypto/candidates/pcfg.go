package candidates

import (
	"container/heap"
	"io"
	"sort"
)

// PCFG is a probabilistic context-free grammar password model in the style of
// Weir et al., "Password Cracking Using Probabilistic Context-Free Grammars"
// (IEEE S&P 2009). A training set is decomposed into base structures — runs of
// letters (L), digits (D), and symbols (S) with their lengths, e.g. "pass12!" ->
// L4 D2 S1 — and per-(class,length) terminal strings, each with a probability
// from its training frequency. Guesses are then emitted in (approximately)
// decreasing probability order: the product of the base-structure probability
// and the chosen terminals' probabilities.
//
// The generation order is Weir's "next" algorithm over pre-terminal structures
// with a priority queue and the pivot trick, which enumerates distinct
// pre-terminals strictly by probability with no duplicates. Everything is
// deterministic given the training set (ties broken lexicographically), so the
// output is reproducible and testable.
type PCFG struct {
	bases     []baseEntry            // base structures, sorted by probability desc
	terminals map[termKey][]terminal // (class,length) -> terminals sorted by prob desc
}

type segment struct {
	class  byte // 'L', 'D', or 'S'
	length int
}

type termKey struct {
	class  byte
	length int
}

type terminal struct {
	s    string
	prob float64
}

type baseEntry struct {
	segs []segment
	prob float64
}

// classOf maps a byte to its character class.
func classOf(b byte) byte {
	switch {
	case (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'):
		return 'L'
	case b >= '0' && b <= '9':
		return 'D'
	default:
		return 'S'
	}
}

// segmentize splits a password into its class-runs (base structure + the actual
// substring for each run).
func segmentize(pw string) ([]segment, []string) {
	var segs []segment
	var parts []string
	i := 0
	for i < len(pw) {
		c := classOf(pw[i])
		j := i + 1
		for j < len(pw) && classOf(pw[j]) == c {
			j++
		}
		segs = append(segs, segment{class: c, length: j - i})
		parts = append(parts, pw[i:j])
		i = j
	}
	return segs, parts
}

// TrainPCFG builds a PCFG from the training words. Empty words are ignored.
func TrainPCFG(words []string) *PCFG {
	baseCount := map[string]int{}
	baseSegs := map[string][]segment{}
	termCount := map[termKey]map[string]int{}
	termTotal := map[termKey]int{}
	totalBase := 0

	for _, w := range words {
		if w == "" {
			continue
		}
		segs, parts := segmentize(w)
		key := baseKey(segs)
		baseCount[key]++
		baseSegs[key] = segs
		totalBase++
		for i, seg := range segs {
			tk := termKey{seg.class, seg.length}
			if termCount[tk] == nil {
				termCount[tk] = map[string]int{}
			}
			termCount[tk][parts[i]]++
			termTotal[tk]++
		}
	}

	p := &PCFG{terminals: map[termKey][]terminal{}}
	if totalBase == 0 {
		return p
	}
	for key, cnt := range baseCount {
		p.bases = append(p.bases, baseEntry{segs: baseSegs[key], prob: float64(cnt) / float64(totalBase)})
	}
	sort.Slice(p.bases, func(i, j int) bool {
		if p.bases[i].prob != p.bases[j].prob {
			return p.bases[i].prob > p.bases[j].prob
		}
		return baseKey(p.bases[i].segs) < baseKey(p.bases[j].segs)
	})
	for tk, counts := range termCount {
		list := make([]terminal, 0, len(counts))
		for s, c := range counts {
			list = append(list, terminal{s: s, prob: float64(c) / float64(termTotal[tk])})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].prob != list[j].prob {
				return list[i].prob > list[j].prob
			}
			return list[i].s < list[j].s
		})
		p.terminals[tk] = list
	}
	return p
}

func baseKey(segs []segment) string {
	b := make([]byte, 0, len(segs)*3)
	for _, s := range segs {
		b = append(b, s.class)
		b = appendInt(b, s.length)
	}
	return string(b)
}

func appendInt(b []byte, n int) []byte {
	if n == 0 {
		return append(b, '0')
	}
	var tmp [12]byte
	i := len(tmp)
	for n > 0 {
		i--
		tmp[i] = byte('0' + n%10)
		n /= 10
	}
	return append(b, tmp[i:]...)
}

// --- probability-ordered generation (Weir's pre-terminal enumeration) ---

type preTerminal struct {
	base    int   // index into p.bases
	idx     []int // chosen terminal index per segment
	pivot   int   // only segments >= pivot may be advanced (dedup)
	prob    float64
	heapPos int
}

type ptHeap []*preTerminal

func (h ptHeap) Len() int           { return len(h) }
func (h ptHeap) Less(i, j int) bool { return h[i].prob > h[j].prob } // max-heap
func (h ptHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *ptHeap) Push(x any)        { *h = append(*h, x.(*preTerminal)) }
func (h *ptHeap) Pop() any {
	old := *h
	n := len(old)
	it := old[n-1]
	old[n-1] = nil
	*h = old[:n-1]
	return it
}

type pcfgSource struct {
	p      *PCFG
	max    int
	h      ptHeap
	out    []byte
	n      int
	inited bool
}

// Source returns a candidate Source that emits up to max PCFG guesses in
// decreasing-probability order (max<=0 means "until the grammar is exhausted",
// which is finite: the product of terminals per base structure).
func (p *PCFG) Source(max int) Source {
	s := &pcfgSource{p: p, max: max}
	s.init()
	return s
}

func (s *pcfgSource) init() {
	s.h = s.h[:0]
	// Seed the heap with the top (all-zero-index) pre-terminal of every base
	// structure whose segments all have at least one known terminal.
	for bi, be := range s.p.bases {
		prob := be.prob
		ok := true
		for _, seg := range be.segs {
			list := s.p.terminals[termKey{seg.class, seg.length}]
			if len(list) == 0 {
				ok = false
				break
			}
			prob *= list[0].prob
		}
		if !ok {
			continue
		}
		pt := &preTerminal{base: bi, idx: make([]int, len(be.segs)), pivot: 0, prob: prob}
		s.h = append(s.h, pt)
	}
	heap.Init(&s.h)
	s.inited = true
	s.n = 0
}

func (s *pcfgSource) Next() ([]byte, error) {
	if (s.max > 0 && s.n >= s.max) || s.h.Len() == 0 {
		return nil, io.EOF
	}
	pt := heap.Pop(&s.h).(*preTerminal)
	be := s.p.bases[pt.base]

	// Materialize the guess.
	s.out = s.out[:0]
	for i, seg := range be.segs {
		s.out = append(s.out, s.p.terminals[termKey{seg.class, seg.length}][pt.idx[i]].s...)
	}

	// Push successors: advance one segment index >= pivot (pivot trick avoids
	// generating the same pre-terminal twice).
	for i := pt.pivot; i < len(be.segs); i++ {
		seg := be.segs[i]
		list := s.p.terminals[termKey{seg.class, seg.length}]
		if pt.idx[i]+1 >= len(list) {
			continue
		}
		child := &preTerminal{base: pt.base, idx: append([]int(nil), pt.idx...), pivot: i}
		child.idx[i]++
		prob := be.prob
		for j, sg := range be.segs {
			prob *= s.p.terminals[termKey{sg.class, sg.length}][child.idx[j]].prob
		}
		child.prob = prob
		heap.Push(&s.h, child)
	}

	s.n++
	return append([]byte(nil), s.out...), nil
}

func (s *pcfgSource) Len() int64 { return -1 }

func (s *pcfgSource) Reset() error {
	s.init()
	return nil
}

// CloneSource returns an independent generator over the same grammar.
func (s *pcfgSource) CloneSource() Source { return s.p.Source(s.max) }
