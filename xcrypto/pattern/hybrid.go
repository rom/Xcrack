package pattern

import (
	"io"

	"github.com/rom/xcrypto/candidates"
)

// maxHybridMask bounds how many mask expansions a hybrid source materializes.
// Hybrid attacks pair a (large) wordlist with a (small) mask, so the mask side
// is held in memory and the wordlist is streamed; a mask whose keyspace exceeds
// this cap is truncated to the first maxHybridMask expansions.
const maxHybridMask = 1 << 20

// Hybrid combines a wordlist with a mask, hashcat's hybrid attack. When append
// is true it yields word+maskExpansion for every word and every expansion of
// the mask (hashcat -a 6, dict+mask); when false it yields maskExpansion+word
// (hashcat -a 7, mask+dict). The wordlist is streamed, so it may be arbitrarily
// large; the mask expansions are materialized (bounded by maxHybridMask).
func Hybrid(words candidates.Source, m *Mask, appnd bool) candidates.Source {
	return &hybridSource{words: words, masks: materializeMask(m), appnd: appnd}
}

func materializeMask(m *Mask) [][]byte {
	if m == nil {
		return nil
	}
	src := m.Source()
	var out [][]byte
	for len(out) < maxHybridMask {
		b, err := src.Next()
		if err != nil {
			break
		}
		out = append(out, append([]byte(nil), b...))
	}
	return out
}

type hybridSource struct {
	words candidates.Source
	masks [][]byte
	appnd bool

	cur     []byte // current word
	j       int    // next mask index for cur
	haveCur bool
}

func (h *hybridSource) Next() ([]byte, error) {
	if len(h.masks) == 0 {
		return nil, io.EOF
	}
	for {
		if !h.haveCur || h.j >= len(h.masks) {
			w, err := h.words.Next()
			if err != nil {
				return nil, err // propagates io.EOF
			}
			h.cur = append(h.cur[:0], w...)
			h.j = 0
			h.haveCur = true
		}
		mask := h.masks[h.j]
		h.j++
		out := make([]byte, 0, len(h.cur)+len(mask))
		if h.appnd {
			out = append(out, h.cur...)
			out = append(out, mask...)
		} else {
			out = append(out, mask...)
			out = append(out, h.cur...)
		}
		return out, nil
	}
}

func (h *hybridSource) Len() int64 {
	wl := h.words.Len()
	if wl < 0 || len(h.masks) == 0 {
		return -1
	}
	n := wl * int64(len(h.masks))
	if n/int64(len(h.masks)) != wl { // overflow
		return -1
	}
	return n
}

func (h *hybridSource) Reset() error {
	h.cur = h.cur[:0]
	h.j = 0
	h.haveCur = false
	return h.words.Reset()
}

// CloneSource clones the hybrid only if the wordlist can be cloned; the mask
// expansions are immutable and shared.
func (h *hybridSource) CloneSource() candidates.Source {
	cl, ok := h.words.(candidates.Cloner)
	if !ok {
		return nil
	}
	w := cl.CloneSource()
	if w == nil {
		return nil
	}
	return &hybridSource{words: w, masks: h.masks, appnd: h.appnd}
}
