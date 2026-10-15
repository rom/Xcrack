package xcrack

import (
	"runtime"
	"sync"
	"time"
)

// Limits bounds the work and resource use of a Process call. They are the
// engine's defense against decompression bombs and runaway recursion. A caller
// may relax them but not below the safety floors applied by (Options).normalize.
type Limits struct {
	MaxDepth       int   // nesting ceiling
	MaxTotalBytes  int64 // cumulative decompressed budget across the whole tree
	MaxNodes       int   // total nodes (entries) produced
	MaxEntrySize   int64 // single-entry content cap
	MaxRatio       int   // reserved: per-entry compression-ratio cap
	MaxCandidates  int64 // candidates tested per encrypted node (0 => unlimited)
	SpillThreshold int64 // reserved: spill intermediates to disk above this size
	TempDir        string
}

// DefaultLimits returns conservative, bomb-resistant defaults.
func DefaultLimits() Limits {
	return Limits{
		MaxDepth:       32,
		MaxTotalBytes:  2 << 30, // 2 GiB
		MaxNodes:       10_000,
		MaxEntrySize:   512 << 20, // 512 MiB
		MaxRatio:       200,
		MaxCandidates:  0,
		SpillThreshold: 64 << 20, // 64 MiB
	}
}

// Budget bounds wall-clock time.
type Budget struct {
	PerFile time.Duration // 0 => none
	Total   time.Duration // 0 => none (also honored via ctx)
}

// accounting is the mutable, shared state for one Process call. All methods are
// safe for concurrent use.
type accounting struct {
	mu         sync.Mutex
	limits     Limits
	totalBytes int64
	nodes      int
	candidates int64
	stats      Stats
}

func newAccounting(l Limits) *accounting {
	return &accounting{limits: l}
}

// reserveBytes adds n to the cumulative byte budget, returning false if that
// would exceed MaxTotalBytes.
func (a *accounting) reserveBytes(n int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.limits.MaxTotalBytes > 0 && a.totalBytes+n > a.limits.MaxTotalBytes {
		return false
	}
	a.totalBytes += n
	a.stats.BytesExtracted = a.totalBytes
	return true
}

// addNode increments the node count, returning false if MaxNodes is exceeded.
func (a *accounting) addNode() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.limits.MaxNodes > 0 && a.nodes+1 > a.limits.MaxNodes {
		return false
	}
	a.nodes++
	a.stats.FilesSeen = a.nodes
	return true
}

func (a *accounting) addCandidates(n int64) {
	a.mu.Lock()
	a.candidates += n
	a.stats.CandidatesTried = a.candidates
	a.mu.Unlock()
}

func (a *accounting) limitHit() {
	a.mu.Lock()
	a.stats.LimitHits++
	a.mu.Unlock()
}

func (a *accounting) snapshot() Stats {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.stats
}

func clampPositive(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func numCPU() int { return runtime.NumCPU() }

// candidatesTried returns the running candidate count (safe for concurrent use).
func (a *accounting) candidatesTried() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.candidates
}
