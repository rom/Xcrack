package msoffice

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// FuzzEntries checks the no-panic invariant: no input, however malformed, may
// crash Detect, Entries, Verify, or Open. The recover guards live in the engine,
// but the parser itself must stay panic-free on hostile input.
func FuzzEntries(f *testing.F) {
	// Seed with the real encrypted fixtures and a few hand-built edge cases.
	for _, name := range []string{
		"rc4cryptoapi_password.doc",
		"rc4cryptoapi_password.xls",
		"rc4cryptoapi_password.ppt",
		"xor_password_123456789012345.xls",
	} {
		if b, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")) // bare CFB signature
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 1024))

	form := New()
	form.Detect(nil)

	f.Fuzz(func(t *testing.T, data []byte) {
		form.Detect(data)
		r := bytes.NewReader(data)
		entries, err := form.Entries(r, int64(len(data)))
		if err != nil {
			return
		}
		for _, e := range entries {
			if e.Verify != nil {
				e.Verify([]byte("Password1234_"))
				e.Verify([]byte("123456789012345"))
			}
			if e.Open != nil {
				rc, oerr := e.Open([]byte("Password1234_"))
				if oerr == nil && rc != nil {
					io.Copy(io.Discard, io.LimitReader(rc, 1<<20))
				}
			}
		}
	})
}
