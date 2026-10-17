package dmg

import (
	"bytes"
	"os"
	"testing"
)

// FuzzProbe exercises the hostile-input surface: Detect plus the $dmg$ line
// finder and parser. A malformed line must never panic — it returns an error,
// which the engine turns into a plain-leaf fallback.
func FuzzProbe(f *testing.F) {
	f.Add([]byte(v1Line))
	f.Add([]byte("x:$dmg$2*20*ab*32*cd*48*ef*14*16*00112233445566778899aabbccddeeff*0"))
	f.Add([]byte("$dmg$"))
	f.Add([]byte("$dmg$1*"))
	f.Add([]byte("name:$dmg$9*nope"))
	f.Add([]byte("no marker here"))
	f.Add([]byte{})
	// On-disk encrcdsa seeds: the 8-byte magic alone, a truncated header, and a
	// real fixture if present — the binary parser must stay panic-free on all.
	f.Add([]byte("encrcdsa"))
	f.Add(append([]byte("encrcdsa\x00\x00\x00\x02"), make([]byte, 80)...))
	if b, err := os.ReadFile("testdata/encrcdsa-aes256.dmg"); err == nil {
		f.Add(b)
	}
	fm := New()
	f.Fuzz(func(t *testing.T, b []byte) {
		fm.Detect(b)
		if ch, err := fm.Probe(bytes.NewReader(b), int64(len(b))); err == nil && ch != nil {
			// Parsed; a Verify must also be panic-free on arbitrary input.
			fm.Verify(ch, []byte("x"))
		}
	})
}
