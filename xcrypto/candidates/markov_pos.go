package candidates

import (
	"container/heap"
	"io"
	"math"
	"sort"
)

// MarkovPos is a position-aware (hashcat-style 2D) Markov model: the transition
// probability of the next byte depends on both the previous byte and the
// position in the string, up to markovPosMax positions (beyond which the last
// position's statistics are reused). It captures position-specific structure
// real passwords have — digits and specials cluster at the end, capitals at the
// start — that the position-independent Markov cannot.
type MarkovPos struct {
	maxPos   int
	logTrans [][257][257]float64 // [pos][prev][next]; index 256 = virtual start/end
}

const markovPosMax = 16

// TrainMarkovPos builds a position-aware model from sample words with add-one
// (Laplace) smoothing. An empty sample yields a uniform model.
func TrainMarkovPos(samples [][]byte) *MarkovPos {
	m := &MarkovPos{maxPos: markovPosMax}
	counts := make([][257][257]float64, m.maxPos)
	for p := range counts {
		for a := 0; a < 257; a++ {
			for b := 0; b < 257; b++ {
				counts[p][a][b] = 1
			}
		}
	}
	clamp := func(p int) int {
		if p >= m.maxPos {
			return m.maxPos - 1
		}
		return p
	}
	for _, w := range samples {
		prev := markovStart
		for i, c := range w {
			counts[clamp(i)][prev][int(c)]++
			prev = int(c)
		}
		counts[clamp(len(w))][prev][markovStart]++ // transition to end at this length
	}
	m.logTrans = make([][257][257]float64, m.maxPos)
	for p := 0; p < m.maxPos; p++ {
		for a := 0; a < 257; a++ {
			var total float64
			for b := 0; b < 257; b++ {
				total += counts[p][a][b]
			}
			for b := 0; b < 257; b++ {
				m.logTrans[p][a][b] = math.Log(counts[p][a][b] / total)
			}
		}
	}
	return m
}

func (m *MarkovPos) at(pos int) *[257][257]float64 {
	if pos >= m.maxPos {
		pos = m.maxPos - 1
	}
	return &m.logTrans[pos]
}

// MarkovGenPos generates candidates from a position-aware model in approximately
// descending probability order (a best-first walk), emitting strings of length
// [minLen,maxLen], at most max of them, considering only each (position,state)'s
// topK most-likely next bytes. It mirrors MarkovGenTopK but consults the
// position-specific transition table.
func MarkovGenPos(m *MarkovPos, minLen, maxLen, max, topK int) Source {
	if minLen < 1 {
		minLen = 1
	}
	if maxLen < minLen {
		maxLen = minLen
	}
	if topK < 1 {
		topK = 1
	}
	if topK > 256 {
		topK = 256
	}
	g := &markovPosGen{m: m, minLen: minLen, maxLen: maxLen, max: max, topK: topK}
	g.reset()
	return g
}

type markovPosGen struct {
	m                   *MarkovPos
	minLen, maxLen, max int
	topK                int
	topNext             [][257][]int // [pos][state] -> top-K next bytes
	h                   mgHeap
	emitted             int
}

func (g *markovPosGen) reset() {
	g.topNext = make([][257][]int, g.m.maxPos)
	for p := 0; p < g.m.maxPos; p++ {
		lt := g.m.at(p)
		for s := 0; s < 257; s++ {
			idx := make([]int, 256)
			for b := 0; b < 256; b++ {
				idx[b] = b
			}
			sort.SliceStable(idx, func(a, b int) bool { return lt[s][idx[a]] > lt[s][idx[b]] })
			if len(idx) > g.topK {
				idx = idx[:g.topK]
			}
			g.topNext[p][s] = idx
		}
	}
	g.h = mgHeap{{bytes: nil, prev: markovStart, score: 0}}
	heap.Init(&g.h)
	g.emitted = 0
}

func (g *markovPosGen) posClamp(p int) int {
	if p >= g.m.maxPos {
		return g.m.maxPos - 1
	}
	return p
}

func (g *markovPosGen) Next() ([]byte, error) {
	for g.h.Len() > 0 {
		if g.max > 0 && g.emitted >= g.max {
			return nil, io.EOF
		}
		it := heap.Pop(&g.h).(*mgItem)
		if it.emit {
			g.emitted++
			return it.bytes, nil
		}
		l := len(it.bytes)
		if l >= g.minLen {
			end := it.score + g.m.at(l)[it.prev][markovStart]
			heap.Push(&g.h, &mgItem{bytes: it.bytes, score: end, emit: true})
		}
		if l < g.maxLen && g.h.Len() < markovHeapCap {
			pos := g.posClamp(l)
			lt := g.m.at(l)
			for _, b := range g.topNext[pos][it.prev] {
				nb := make([]byte, l+1)
				copy(nb, it.bytes)
				nb[l] = byte(b)
				heap.Push(&g.h, &mgItem{bytes: nb, prev: b, score: it.score + lt[it.prev][b]})
			}
		}
	}
	return nil, io.EOF
}

func (g *markovPosGen) Len() int64 {
	if g.max > 0 {
		return int64(g.max)
	}
	return -1
}

func (g *markovPosGen) Reset() error { g.reset(); return nil }

func (g *markovPosGen) CloneSource() Source {
	return MarkovGenPos(g.m, g.minLen, g.maxLen, g.max, g.topK)
}
