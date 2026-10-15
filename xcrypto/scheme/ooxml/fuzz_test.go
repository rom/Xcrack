package ooxml

import "testing"

func FuzzParseEncryptionInfo(f *testing.F) {
	if info, _, err := EncryptAgile([]byte("p"), []byte("PK\x03\x04pkg"), 10); err == nil {
		f.Add(info)
	}
	if info, _, err := EncryptStandard([]byte("p"), []byte("pkg"), 16); err == nil {
		f.Add(info)
	}
	f.Add([]byte{})
	f.Add([]byte{0x04, 0x00, 0x04, 0x00, 0x40, 0, 0, 0})
	f.Add([]byte{0x03, 0x00, 0x02, 0x00, 0x24, 0, 0, 0})

	f.Fuzz(func(t *testing.T, b []byte) {
		i, err := ParseEncryptionInfo(b)
		if err != nil || i == nil {
			return
		}
		// spin count is bounded by the parser, so this terminates quickly
		i.Verify([]byte("p"))
	})
}
