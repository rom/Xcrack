package age

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// FuzzProbe checks that Detect/Probe/Verify never panic on hostile input.
func FuzzProbe(f *testing.F) {
	if b, err := os.ReadFile(filepath.Join("testdata", "hello.age")); err == nil {
		f.Add(b)
	}
	f.Add([]byte("age-encryption.org/v1\n"))
	f.Add([]byte("age-encryption.org/v1\n-> scrypt AAAA 18\n--- \n"))
	f.Add([]byte{})

	form := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		form.Detect(data)
		ch, err := form.Probe(bytes.NewReader(data), int64(len(data)))
		if err != nil || ch == nil {
			return
		}
		// Keep the fuzz fast: don't run scrypt at a high work factor.
		if ch.KDF.Iterations <= 16 {
			form.Verify(ch, []byte("x"))
		}
	})
}
