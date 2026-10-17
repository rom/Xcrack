package access

import "testing"

// FuzzRecoverJetPassword checks that the Jet header decoder never panics on
// hostile or truncated input — it parses attacker-controlled header bytes.
func FuzzRecoverJetPassword(f *testing.F) {
	f.Add(jet4Fixture)
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00})
	f.Add(append([]byte("\x00\x01\x00\x00Standard Jet DB\x00"), make([]byte, 8)...))
	f.Add(append([]byte("\x00\x00\x00\x00Standard Jet DB\x00"), make([]byte, 200)...))

	form := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		form.Detect(data)
		Variant(data)
		RecoverJetPassword(data)
	})
}
