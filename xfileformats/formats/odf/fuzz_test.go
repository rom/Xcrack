package odf

import (
	"bytes"
	"testing"
)

func FuzzEntries(f *testing.F) {
	if data, err := BuildEncryptedODF([]byte("p"), []byte("<x/>"), 100); err == nil {
		f.Add(data)
	}
	if data, err := BuildEncryptedODFGCM([]byte("p"), []byte("<x/>"), 100); err == nil {
		f.Add(data)
	}
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	fm := New()
	f.Fuzz(func(t *testing.T, b []byte) {
		fm.Detect(b)
		entries, err := fm.Entries(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Verify != nil {
				e.Verify([]byte("x"))
			}
		}
	})
}
