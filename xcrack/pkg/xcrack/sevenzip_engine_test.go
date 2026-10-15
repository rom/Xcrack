package xcrack

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestEncrypted7zEngine decrypts a real 7z (created by the 7z CLI) through the
// full engine. Skipped when 7z is absent; CI installs it.
func TestEncrypted7zEngine(t *testing.T) {
	bin, err := exec.LookPath("7z")
	if err != nil {
		t.Skip("7z CLI not available")
	}
	dir := t.TempDir()
	content := []byte("the payload inside an encrypted 7z archive")
	os.WriteFile(filepath.Join(dir, "doc.txt"), content, 0o600)
	cmd := exec.Command(bin, "a", "-pLetMeIn", "a.7z", "doc.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z: %v\n%s", err, out)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "a.7z"))

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("nope", "LetMeIn"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Root.Format != "7z" {
		t.Fatalf("root format = %q, want 7z", res.Root.Format)
	}
	var got []byte
	res.Root.Walk(func(n *Node) {
		if n.WasEncrypted && n.Status == StatusDecrypted && n.Content != nil {
			rc, _ := n.Content.Open()
			got, _ = readAllRC(rc)
		}
	})
	if !bytes.Equal(got, content) {
		t.Fatalf("decrypted 7z content mismatch; tree:\n%s", dumpTree(res.Root))
	}
}
