package zip

import (
	stdzip "archive/zip"
	"bytes"
	"testing"
)

// FuzzEntries fuzzes central-directory parsing and the WinZip-AES extra-field /
// path-sanitization code. It does not decompress or decrypt (those bomb-prone
// paths are fuzzed through the engine, where the size budget applies).
func FuzzEntries(f *testing.F) {
	var zb bytes.Buffer
	zw := stdzip.NewWriter(&zb)
	w, _ := zw.Create("a/b.txt")
	w.Write([]byte("hello"))
	zw.Close()
	f.Add(zb.Bytes())
	f.Add([]byte("PK\x03\x04"))
	f.Add([]byte("PK\x05\x06"))
	f.Add([]byte{})

	fmt := New()
	f.Fuzz(func(t *testing.T, b []byte) {
		fmt.Detect(b)
		entries, err := fmt.Entries(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return
		}
		for _, e := range entries {
			_ = e.Path
			_ = e.Challenge
		}
	})
}
