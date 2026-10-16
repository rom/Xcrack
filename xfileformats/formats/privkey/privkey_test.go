package privkey

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFormat(t *testing.T) {
	for _, f := range []string{"pkcs8_aes.pem", "trad_rsa.pem"} {
		data, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		fm := New()
		if c, ok := fm.Detect(data[:64]); !ok || c < 0.5 {
			t.Fatalf("%s: Detect=%v,%v", f, c, ok)
		}
		ra := bytes.NewReader(data)
		ch, err := fm.Probe(ra, int64(len(data)))
		if err != nil {
			t.Fatalf("%s: Probe: %v", f, err)
		}
		ok, key, err := fm.Verify(ch, []byte("Hunter2!"))
		if err != nil || !ok {
			t.Fatalf("%s: Verify ok=%v err=%v", f, ok, err)
		}
		if bad, _, _ := fm.Verify(ch, []byte("nope")); bad {
			t.Fatalf("%s: wrong passphrase verified", f)
		}
		r, err := fm.Decrypt(ra, int64(len(data)), ch, key)
		if err != nil {
			t.Fatalf("%s: Decrypt: %v", f, err)
		}
		out := make([]byte, 8192)
		n, _ := r.Read(out)
		if !bytes.Contains(out[:n], []byte("PRIVATE KEY")) {
			t.Fatalf("%s: not a PEM key", f)
		}
	}
}

func FuzzProbe(f *testing.F) {
	for _, n := range []string{"pkcs8_aes.pem", "trad_rsa.pem"} {
		if b, err := os.ReadFile(filepath.Join("testdata", n)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(""))
	ff := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		ra := bytes.NewReader(data)
		if ch, err := ff.Probe(ra, int64(len(data))); err == nil && ch != nil {
			ff.Verify(ch, []byte("x"))
		}
	})
}
