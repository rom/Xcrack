package sshkey

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFormatProbeVerifyDecrypt(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "enc_ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	f := New()
	if c, ok := f.Detect(data[:64]); !ok || c < 0.5 {
		t.Fatalf("Detect = %v, %v", c, ok)
	}
	ra := bytes.NewReader(data)
	ch, err := f.Probe(ra, int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	ok, key, err := f.Verify(ch, []byte("correct horse"))
	if err != nil || !ok {
		t.Fatalf("Verify: ok=%v err=%v", ok, err)
	}
	if bad, _, _ := f.Verify(ch, []byte("nope")); bad {
		t.Fatal("wrong passphrase verified")
	}
	r, err := f.Decrypt(ra, int64(len(data)), ch, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	out := make([]byte, 4096)
	n, _ := r.Read(out)
	if !bytes.Contains(out[:n], []byte("PRIVATE KEY")) {
		t.Fatalf("decrypted output not a PEM key: %s", out[:n])
	}
}

func FuzzParse(f *testing.F) {
	for _, n := range []string{"enc_ed25519"} {
		if b, err := os.ReadFile(filepath.Join("testdata", n)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"))
	f.Add([]byte(""))
	ff := New()
	f.Fuzz(func(t *testing.T, data []byte) {
		ra := bytes.NewReader(data)
		if ch, err := ff.Probe(ra, int64(len(data))); err == nil && ch != nil {
			ff.Verify(ch, []byte("x"))
		}
	})
}
