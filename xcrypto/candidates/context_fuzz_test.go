package candidates

import "testing"

// Invariant: the context parsers are pointed at hostile/arbitrary bytes (file
// names and harvested plaintext), so they must never panic and must terminate
// with bounded output.

func FuzzFromText(f *testing.F) {
	for _, s := range []string{
		"the password is swordfish",
		`passphrase: "correct horse battery staple"`,
		"pwd=letmein pin 4321 code: 9",
		"password", "pw", "", "pass pass pass",
		"key:\x00\xff\x01 garbage", "pw" + string(make([]byte, 5000)),
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		out := FromText(data, 0)
		if len(out) > 64 {
			t.Fatalf("FromText returned %d candidates, want <= 64", len(out))
		}
		for _, c := range out {
			if len(c) > 64 {
				t.Fatalf("candidate exceeds 64 bytes: %d", len(c))
			}
		}
	})
}

func FuzzFromName(f *testing.F) {
	for _, s := range []string{
		"invoice_2024.pdf.zip", "a!/b!/c.txt", "....", "", "/////",
		"name with spaces.doc", string([]byte{0x00, 0x2f, 0xff}),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		_ = FromName(name)
	})
}
