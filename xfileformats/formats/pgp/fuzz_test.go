package pgp

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzProbe checks that Detect/Probe/Verify never panic on hostile input.
func FuzzProbe(f *testing.F) {
	if b, err := os.ReadFile(filepath.Join("testdata", "hello.gpg")); err == nil {
		f.Add(b)
	}
	f.Add([]byte{0x8c, 0x0d, 0x04, 0x09, 0x03})
	f.Add([]byte{0xc3, 0x05})
	f.Add([]byte{})

	form := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		form.Detect(data)
		ch, err := form.Probe(bytes.NewReader(data), int64(len(data)))
		if err != nil || ch == nil {
			return
		}
		form.Verify(ch, []byte("x"))
	})
}
