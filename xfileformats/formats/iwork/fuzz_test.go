package iwork

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// FuzzProbe enforces the no-panic invariant on hostile input: Probe must never
// panic and must always either return a Challenge or an error.
func FuzzProbe(f *testing.F) {
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("not a zip"))
	if v, err := hex.DecodeString(pagesVerifierHex); err == nil {
		f.Add(zipOfRaw(map[string][]byte{".iwpv2": v, "Index/Document.iwa": []byte("x")}))
	}
	fm := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, err := fm.Probe(bytes.NewReader(data), int64(len(data)))
		if err == nil && ch == nil {
			t.Fatal("Probe returned nil Challenge and nil error")
		}
		if ch != nil {
			// Verify must not panic on any probed challenge either.
			_, _, _ = fm.Verify(ch, []byte("x"))
		}
	})
}
