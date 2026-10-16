package candidates

import (
	"container/heap"
	"io"
	"sort"
)

// MarkovGen returns a Source that generates candidates from a trained Markov
// model in approximately descending probability order (a best-first walk of the
// model). It emits strings of length [minLen,maxLen], at most max of them,
// considering only each state's topK most-likely next bytes (pruning keeps the
// frontier bounded). It is a generator — unlike ByScore, which only reorders an
// existing list.
func MarkovGen(m *Markov, minLen, maxLen, max int) Source {
	return MarkovGenTopK(m, minLen, maxLen, max, 15)
}

// MarkovGenTopK is MarkovGen with an explicit per-state branching factor.
func MarkovGenTopK(m *Markov, minLen, maxLen, max, topK int) Source {
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
	g := &markovGen{m: m, minLen: minLen, maxLen: maxLen, max: max, topK: topK}
	g.reset()
	return g
}

const markovHeapCap = 1 << 20

type mgItem struct {
	bytes []byte
	prev  int     // previous byte state (markovStart at the root)
	score float64 // cumulative log-probability
	emit  bool    // true => a finished candidate ready to yield
}

type mgHeap []*mgItem

func (h mgHeap) Len() int { return len(h) }
func (h mgHeap) Less(i, j int) bool {
	if h[i].score != h[j].score {
		return h[i].score > h[j].score // max-heap on probability
	}
	// Deterministic tie-breaks.
	if c := string(h[i].bytes); c != string(h[j].bytes) {
		return c < string(h[j].bytes)
	}
	return h[i].emit && !h[j].emit
}
func (h mgHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *mgHeap) Push(x any)   { *h = append(*h, x.(*mgItem)) }
func (h *mgHeap) Pop() any     { old := *h; n := len(old); it := old[n-1]; *h = old[:n-1]; return it }

type markovGen struct {
	m                   *Markov
	minLen, maxLen, max int
	topK                int
	topNext             [257][]int // precomputed top-K next bytes per state
	h                   mgHeap
	emitted             int
}

func (g *markovGen) reset() {
	// Precompute each state's top-K next bytes by transition probability.
	for s := 0; s < 257; s++ {
		idx := make([]int, 256) // real bytes only (exclude the end state 256)
		for b := 0; b < 256; b++ {
			idx[b] = b
		}
		sort.SliceStable(idx, func(a, b int) bool {
			return g.m.logTrans[s][idx[a]] > g.m.logTrans[s][idx[b]]
		})
		if len(idx) > g.topK {
			idx = idx[:g.topK]
		}
		g.topNext[s] = idx
	}
	g.h = mgHeap{{bytes: nil, prev: markovStart, score: 0}}
	heap.Init(&g.h)
	g.emitted = 0
}

func (g *markovGen) Next() ([]byte, error) {
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
		// This prefix can terminate as a candidate once it is long enough.
		if l >= g.minLen {
			end := it.score + g.m.logTrans[it.prev][markovStart]
			heap.Push(&g.h, &mgItem{bytes: it.bytes, score: end, emit: true})
		}
		// Extend it with the likeliest next bytes (bounded frontier).
		if l < g.maxLen && g.h.Len() < markovHeapCap {
			for _, b := range g.topNext[it.prev] {
				nb := make([]byte, l+1)
				copy(nb, it.bytes)
				nb[l] = byte(b)
				heap.Push(&g.h, &mgItem{
					bytes: nb,
					prev:  b,
					score: it.score + g.m.logTrans[it.prev][b],
				})
			}
		}
	}
	return nil, io.EOF
}

func (g *markovGen) Len() int64 {
	if g.max > 0 {
		return int64(g.max)
	}
	return -1
}

func (g *markovGen) Reset() error { g.reset(); return nil }

func (g *markovGen) CloneSource() Source {
	return MarkovGenTopK(g.m, g.minLen, g.maxLen, g.max, g.topK)
}
