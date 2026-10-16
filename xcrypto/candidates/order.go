package candidates

import "sort"

// Scorer assigns a priority to a candidate; higher is tried first.
type Scorer func(candidate []byte) float64

// ByScore drains src (up to max candidates) and returns a new source that yields
// the same candidates ordered by descending Scorer value, ties broken by
// original order (stable) for determinism. It is for finite sources whose head
// is worth reordering -- e.g. a wordlist reordered by a statistical model so the
// likeliest passwords are tried first. max<=0 applies a safety cap.
//
// ByScore consumes src. The returned source is in-memory and cloneable (so it
// works with the engine's sibling parallelism).
func ByScore(src Source, score Scorer, max int) Source {
	const defaultMax = 1 << 20
	if max <= 0 || max > defaultMax {
		max = defaultMax
	}
	if src == nil || score == nil {
		return Explicit()
	}
	type scored struct {
		item  []byte
		score float64
		idx   int
	}
	var items []scored
	for len(items) < max {
		b, err := src.Next()
		if err != nil {
			break
		}
		cp := append([]byte(nil), b...)
		items = append(items, scored{item: cp, score: score(cp), idx: len(items)})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].idx < items[j].idx
	})
	out := make([][]byte, len(items))
	for i := range items {
		out[i] = items[i].item
	}
	return Bytes(out...)
}
