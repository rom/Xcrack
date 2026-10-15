package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/rom/xcrypto/candidates"
)

// FuzzProcess drives the whole pipeline -- detection, every format parser,
// bounded decompression, crypto verification, and recursion -- on arbitrary
// input under tight limits and a deadline. The invariant: no panic escapes (the
// recover() guards turn parser panics into error nodes), and it terminates
// within bounded resources.
func FuzzProcess(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("PK\x05\x06"))
	f.Add([]byte("%PDF-1.7\n/Encrypt 6 0 R"))
	f.Add([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"))
	f.Add([]byte("hello, not a recognized format"))
	f.Add([]byte{})
	var zb bytes.Buffer
	zw := stdzip.NewWriter(&zb)
	w, _ := zw.Create("f.txt")
	w.Write([]byte("data"))
	zw.Close()
	f.Add(zb.Bytes())

	f.Fuzz(func(t *testing.T, b []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		opts := Options{
			Workers:  2,
			MaxProcs: 2,
			Limits: Limits{
				MaxDepth: 8, MaxTotalBytes: 4 << 20, MaxEntrySize: 1 << 20,
				MaxNodes: 200, MaxCandidates: 50,
			},
			Budget: Budget{PerFile: 2 * time.Second},
		}
		res, err := Process(ctx, bytes.NewReader(b), int64(len(b)), candidates.Explicit("x", "infected", ""), opts)
		if err != nil {
			return
		}
		if res != nil {
			res.Close()
		}
	})
}
