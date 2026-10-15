package ooxml

import (
	"bytes"
	"testing"
)

func FuzzProbe(f *testing.F) {
	if doc, err := BuildEncryptedAgile([]byte("p"), []byte("PK\x03\x04pkg"), 10); err == nil {
		f.Add(doc)
	}
	f.Add([]byte{})
	f.Add([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"))
	f.Add(append([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"), make([]byte, 600)...))

	fmt := New()
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, err := fmt.Probe(bytes.NewReader(b), int64(len(b)))
		if err != nil || ch == nil {
			return
		}
		fmt.Verify(ch, []byte("p"))
	})
}
