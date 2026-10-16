package p12

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestFormat(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "test.p12"))
	if err != nil {
		t.Fatal(err)
	}
	f := New()
	if c, ok := f.Detect(data[:256]); !ok || c < 0.5 {
		t.Fatalf("Detect=%v,%v", c, ok)
	}
	ra := bytes.NewReader(data)
	ch, err := f.Probe(ra, int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ok, _, _ := f.Verify(ch, []byte("Hunter2!")); !ok {
		t.Fatal("correct password did not verify")
	}
	if bad, _, _ := f.Verify(ch, []byte("nope")); bad {
		t.Fatal("wrong password verified")
	}
}
