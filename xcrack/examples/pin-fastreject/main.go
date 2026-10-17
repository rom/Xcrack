// Command pin-fastreject shows Options.FastReject: a cheap, side-effect-free
// pre-check that prunes doomed candidates before the expensive KDF ever runs.
// The scenario is domain knowledge — "the secret is an N-digit numeric PIN" —
// applied to a broad brute-force source over letters+digits: FastReject passes
// only the all-digit candidates of the right length, so the engine spends its
// KDF budget on the ~10^N real PINs instead of the whole alphabet space. A
// rejected candidate can never be the password, so this only ever speeds a
// search; it cannot cause a miss or a false positive.
//
// Usage:
//
//	pin-fastreject -len N <target>
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"sync/atomic"

	"github.com/rom/xcrack/pkg/xcrack"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

func main() {
	pinLen := flag.Int("len", 4, "PIN length (also the brute-force token length)")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: pin-fastreject -len N <target>")
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read target: %v\n", err)
		os.Exit(1)
	}

	var generated, tested atomic.Int64
	opts := xcrack.Options{
		// Count every candidate the engine actually derives a key for. The gap
		// between this and `generated` is what FastReject saved.
		OnProgress: func(p xcrack.Progress) { tested.Store(p.CandidatesTried) },
		// The domain constraint: keep only all-digit candidates of the PIN length.
		FastReject: func(_ string, cand []byte) bool {
			generated.Add(1)
			if len(cand) != *pinLen {
				return true
			}
			for _, b := range cand {
				if b < '0' || b > '9' {
					return true // not a PIN: reject before the KDF
				}
			}
			return false
		},
	}

	src := newBrute(alphabet, *pinLen)
	fmt.Fprintf(os.Stderr, "brute keyspace %d; FastReject will let ~%d PINs reach the KDF\n", src.Len(), pow(10, *pinLen))

	res, err := xcrack.Process(context.Background(), bytes.NewReader(data), int64(len(data)), src, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process: %v\n", err)
		os.Exit(1)
	}
	defer res.Close()

	fmt.Fprintf(os.Stderr, "FastReject screened %d candidate(s); %d reached the KDF\n", generated.Load(), tested.Load())
	if pws := res.Passwords(); len(pws) > 0 {
		fmt.Printf("recovered PIN: %s\n", pws[0])
		return
	}
	fmt.Println("no PIN found in the keyspace")
	os.Exit(1)
}

// brute is a candidates.Source over alphabet^length, in odometer order. It shows
// how little an embedder needs to implement to plug a custom keyspace into the
// engine: Next / Len / Reset.
type brute struct {
	alpha  []byte
	length int
	i      int64
	total  int64
}

func newBrute(alpha string, length int) *brute {
	return &brute{alpha: []byte(alpha), length: length, total: pow(int64(len(alpha)), length)}
}

func (b *brute) Len() int64   { return b.total }
func (b *brute) Reset() error { b.i = 0; return nil }

func (b *brute) Next() ([]byte, error) {
	if b.i >= b.total {
		return nil, io.EOF
	}
	out := make([]byte, b.length)
	n := b.i
	base := int64(len(b.alpha))
	for p := b.length - 1; p >= 0; p-- {
		out[p] = b.alpha[n%base]
		n /= base
	}
	b.i++
	return out, nil
}

func pow[T int | int64](base T, exp int) T {
	r := T(1)
	for i := 0; i < exp; i++ {
		r *= base
	}
	return r
}
