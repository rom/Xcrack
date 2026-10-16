package cfb

import (
	"bytes"
	"testing"
)

func FuzzOpen(f *testing.F) {
	f.Add(Build([]StreamEntry{
		{Name: "EncryptionInfo", Data: []byte("small stream")},
		{Name: "EncryptedPackage", Data: bytes.Repeat([]byte("z"), 6000)},
	}))
	f.Add([]byte{})
	f.Add([]byte(sig))
	f.Add(append([]byte(sig), make([]byte, 600)...))
	f.Add(difatBomb()) // oversized/cyclic DIFAT chain (regression)

	f.Fuzz(func(t *testing.T, b []byte) {
		cf, err := Open(b)
		if err != nil || cf == nil {
			return
		}
		for _, n := range cf.Names() {
			cf.Stream(n)
		}
	})
}
