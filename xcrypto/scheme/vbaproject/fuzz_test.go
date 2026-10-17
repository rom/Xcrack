package vbaproject

import "testing"

// FuzzParseDPB checks the DPB decoder never panics on hostile/truncated input.
func FuzzParseDPB(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xA7, 0xA5, 0x9B, 0x3F, 0xD4, 0x52, 0x8F})
	f.Add(make([]byte, 29))
	for _, fx := range hashedFixtures {
		b := mustHexNoT(fx.dpb)
		if b != nil {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		pw, err := ParseDPB(data)
		if err == nil && pw.Kind == KindHash {
			// A hashed result must carry a well-formed key/hash; Verify must not panic.
			_ = Verify(pw.Key, pw.Hash, []byte("x"))
		}
	})
}

func mustHexNoT(s string) []byte {
	out := make([]byte, 0, len(s)/2)
	hexv := func(c byte) (byte, bool) {
		switch {
		case c >= '0' && c <= '9':
			return c - '0', true
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10, true
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10, true
		}
		return 0, false
	}
	if len(s)%2 != 0 {
		return nil
	}
	for i := 0; i < len(s); i += 2 {
		hi, ok1 := hexv(s[i])
		lo, ok2 := hexv(s[i+1])
		if !ok1 || !ok2 {
			return nil
		}
		out = append(out, hi<<4|lo)
	}
	return out
}
