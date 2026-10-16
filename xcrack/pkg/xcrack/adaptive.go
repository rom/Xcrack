package xcrack

import (
	"sort"
	"sync"
)

// learnedSet is a Pool-level, thread-safe store of passwords recovered anywhere
// in a run. With Options.CorpusPromotion enabled it drives corpus-wide
// promotion: a password that unlocked one file is tried first on every other
// file (and inner node) in the same Pool, and the set is ordered by observed
// success so the most repeatedly-effective passwords come first ("order
// candidates by observed crackability"). It is bounded, so a pathological run
// cannot grow it without limit; once full, further novel passwords are dropped
// (the already-proven ones are the valuable ones to keep).
type learnedSet struct {
	mu    sync.Mutex
	hits  map[string]int
	order []string // insertion order, for a stable tiebreak among equal hit counts
	max   int
}

func newLearnedSet(max int) *learnedSet {
	if max <= 0 {
		max = 1 << 16
	}
	return &learnedSet{hits: make(map[string]int), max: max}
}

// add records one successful use of pw, incrementing its hit count (and
// inserting it on first sight, subject to the size bound).
func (l *learnedSet) add(pw string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.hits[pw]; !ok {
		if len(l.order) >= l.max {
			return
		}
		l.order = append(l.order, pw)
	}
	l.hits[pw]++
}

// snapshotOrdered returns the learned passwords most-successful-first. Ties keep
// insertion order (a stable sort), so the result is deterministic for a given
// sequence of adds.
func (l *learnedSet) snapshotOrdered() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.order))
	copy(out, l.order)
	sort.SliceStable(out, func(i, j int) bool { return l.hits[out[i]] > l.hits[out[j]] })
	return out
}

// len reports how many distinct passwords have been learned.
func (l *learnedSet) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.order)
}
