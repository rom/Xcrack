package keepass

import (
	"bytes"
	"os"
	"testing"
)

func FuzzProbe(f *testing.F) {
	if data, err := os.ReadFile("testdata/pykeepass-argon2d.kdbx"); err == nil {
		f.Add(data)
	}
	f.Add([]byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x00, 0x00, 0x04, 0x00})
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte{})
	fm := New()
	f.Fuzz(func(t *testing.T, b []byte) {
		// Exercise the hostile-input parser only (Detect + Probe/Parse of the
		// header and KDF VariantDictionary). Verify is intentionally not called:
		// it runs the (bounded but heavy) Argon2 KDF, which is validated
		// separately and is not the parsing surface under test here.
		fm.Detect(b)
		fm.Probe(bytes.NewReader(b), int64(len(b)))
	})
}
