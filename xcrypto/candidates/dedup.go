package candidates

// maxDedupTracked bounds the dedup set's memory. Once this many distinct
// candidates have been seen, dedup stops tracking and passes everything through
// (so a huge keyspace can't exhaust memory). Finite wordlists stay fully deduped.
const maxDedupTracked = 8 << 20

// Dedup wraps src and skips candidates it has already yielded, so stacked
// wordlists / masks / rules don't retest the same string. Deduplication is
// bounded (see maxDedupTracked); beyond the cap it degrades to a pass-through.
func Dedup(src Source) Source {
	return &dedupSource{src: src, seen: make(map[string]struct{})}
}

type dedupSource struct {
	src  Source
	seen map[string]struct{}
	full bool // cap reached; stop tracking
}

func (d *dedupSource) Next() ([]byte, error) {
	for {
		b, err := d.src.Next()
		if err != nil {
			return nil, err
		}
		if d.full {
			return b, nil
		}
		k := string(b)
		if _, ok := d.seen[k]; ok {
			continue
		}
		d.seen[k] = struct{}{}
		if len(d.seen) >= maxDedupTracked {
			d.full = true
		}
		return b, nil
	}
}

func (d *dedupSource) Len() int64 { return -1 }

func (d *dedupSource) Reset() error {
	d.seen = make(map[string]struct{})
	d.full = false
	return d.src.Reset()
}

func (d *dedupSource) CloneSource() Source {
	c, ok := d.src.(Cloner)
	if !ok {
		return nil
	}
	cl := c.CloneSource()
	if cl == nil {
		return nil
	}
	return &dedupSource{src: cl, seen: make(map[string]struct{})}
}
