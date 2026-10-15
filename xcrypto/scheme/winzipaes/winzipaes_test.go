package winzipaes

import (
	"bytes"
	"testing"
)

func TestRoundTripAllStrengths(t *testing.T) {
	for _, s := range []byte{1, 2, 3} { // AES-128/192/256
		s := s
		p := Params{Strength: s, ActualMethod: 8, VendorVer: 2}
		t.Run(p.SchemeName(), func(t *testing.T) {
			pw := []byte("Welcome1")
			payload := bytes.Repeat([]byte("secret-"), 50)
			salt := make([]byte, p.SaltLen())
			for i := range salt {
				salt[i] = byte(i * 7)
			}
			raw, err := EncryptRaw(pw, p, salt, payload)
			if err != nil {
				t.Fatal(err)
			}
			ok, err := Verify(pw, p, raw)
			if err != nil || !ok {
				t.Fatalf("Verify(correct) ok=%v err=%v", ok, err)
			}
			if ok, _ := Verify([]byte("wrong"), p, raw); ok {
				t.Fatal("Verify(wrong) = true")
			}
			got, err := Decrypt(pw, p, raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("Decrypt mismatch (%d bytes vs %d)", len(got), len(payload))
			}
			if _, err := Decrypt([]byte("wrong"), p, raw); err == nil {
				t.Fatal("Decrypt(wrong) should fail")
			}
		})
	}
}
