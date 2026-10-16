package xcrack

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestAgeEngine decrypts a passphrase-protected age file (produced by the real
// age CLI) through the full engine.
func TestAgeEngine(t *testing.T) {
	path := filepath.Join("..", "..", "..", "xfileformats", "formats", "age", "testdata", "hello.age")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	const pass = "correct horse battery staple"
	const plain = "the quick brown fox jumps over the lazy dog\n"

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong", pass), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	if res.Root.Format != "age" {
		t.Fatalf("root format = %q, want age; tree:\n%s", res.Root.Format, dumpTree(res.Root))
	}
	if !res.Root.WasEncrypted || res.Root.Status != StatusDecrypted {
		t.Fatalf("root not decrypted; tree:\n%s", dumpTree(res.Root))
	}
	if res.Root.Password != pass {
		t.Fatalf("password = %q, want %q", res.Root.Password, pass)
	}
	if res.Root.Content == nil {
		t.Fatal("no content")
	}
	rc, _ := res.Root.Content.Open()
	got, _ := readAllRC(rc)
	if !bytes.Equal(got, []byte(plain)) {
		t.Fatalf("decrypted content = %q, want %q", got, plain)
	}
}
