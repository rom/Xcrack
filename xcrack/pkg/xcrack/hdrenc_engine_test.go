package xcrack

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestHeaderEncrypted7zEngine decrypts a header-encrypted 7z (7z -mhe=on)
// through the full engine: the whole archive is behind one password, and its
// member surfaces as nested decrypted content.
func TestHeaderEncrypted7zEngine(t *testing.T) {
	path := filepath.Join("..", "..", "..", "xfileformats", "formats", "archive", "testdata", "hdr.7z")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	const pass = "Hunter2"
	const content = "secret payload inside an encrypted-header archive\n"

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("nope", pass), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	foundPass := false
	for _, p := range res.Passwords() {
		if p == pass {
			foundPass = true
		}
	}
	if !foundPass {
		t.Fatalf("password not recovered; tree:\n%s", dumpTree(res.Root))
	}

	var found []byte
	res.Root.Walk(func(n *Node) {
		if n.Content != nil {
			rc, _ := n.Content.Open()
			b, _ := readAllRC(rc)
			if bytes.Equal(b, []byte(content)) {
				found = b
			}
		}
	})
	if found == nil {
		t.Fatalf("decrypted member not found in tree:\n%s", dumpTree(res.Root))
	}
}
