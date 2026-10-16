package xcrack

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestPGPEngine decrypts a symmetric OpenPGP message (gpg -c) through the engine.
func TestPGPEngine(t *testing.T) {
	path := filepath.Join("..", "..", "..", "xfileformats", "formats", "pgp", "testdata", "hello.gpg")
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

	if res.Root.Format != "openpgp" {
		t.Fatalf("root format = %q, want openpgp; tree:\n%s", res.Root.Format, dumpTree(res.Root))
	}
	if res.Root.Password != pass || res.Root.Status != StatusDecrypted {
		t.Fatalf("not decrypted with the right password; tree:\n%s", dumpTree(res.Root))
	}
	rc, _ := res.Root.Content.Open()
	got, _ := readAllRC(rc)
	if !bytes.Equal(got, []byte(plain)) {
		t.Fatalf("decrypted content = %q, want %q", got, plain)
	}
}
