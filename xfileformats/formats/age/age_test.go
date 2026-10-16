package age

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

const (
	fixturePass  = "correct horse battery staple"
	fixturePlain = "the quick brown fox jumps over the lazy dog\n"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "hello.age"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	return b
}

func TestAgeFormatRoundTrip(t *testing.T) {
	data := fixture(t)
	f := New()
	if conf, ok := f.Detect(data); !ok || conf <= 0 {
		t.Fatalf("Detect = %v, %v", conf, ok)
	}
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	ok, key, err := f.Verify(ch, []byte(fixturePass))
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want ok", ok, err)
	}
	if ok2, _, _ := f.Verify(ch, []byte("wrong")); ok2 {
		t.Fatal("Verify accepted a wrong passphrase")
	}
	r, err := f.Decrypt(bytes.NewReader(data), int64(len(data)), ch, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, []byte(fixturePlain)) {
		t.Fatalf("decrypted = %q, want %q", got, fixturePlain)
	}
}
