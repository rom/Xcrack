package xcrack

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// fixturePath locates a file in the msoffice format's testdata from within the
// xcrack module (they share the repository via go.work).
func fixturePath(name string) string {
	return filepath.Join("..", "..", "..", "xfileformats", "formats", "msoffice", "testdata", name)
}

// TestLegacyOfficeEngine runs an encrypted legacy .doc through the full engine:
// it must be detected as msoffice, the password recovered, and the decrypted
// WordDocument stream surfaced as scannable content (its FIB magic intact).
func TestLegacyOfficeEngine(t *testing.T) {
	data, err := os.ReadFile(fixturePath("rc4cryptoapi_password.doc"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong", "Password1234_"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	if res.Root.Format != "msoffice" {
		t.Fatalf("root format = %q, want msoffice; tree:\n%s", res.Root.Format, dumpTree(res.Root))
	}
	if len(res.Root.Children) == 0 {
		t.Fatalf("no decrypted streams; tree:\n%s", dumpTree(res.Root))
	}

	var wordDoc []byte
	var decryptedCount int
	for _, c := range res.Root.Children {
		if c.WasEncrypted && c.Status == StatusDecrypted {
			decryptedCount++
			if c.Password != "Password1234_" {
				t.Errorf("child %q password = %q, want Password1234_", c.Path, c.Password)
			}
		}
		if filepath.Base(c.Path) == "WordDocument" && c.Content != nil {
			rc, _ := c.Content.Open()
			wordDoc, _ = readAllRC(rc)
		}
	}
	if decryptedCount == 0 {
		t.Fatalf("no decrypted child nodes; tree:\n%s", dumpTree(res.Root))
	}
	// The decrypted WordDocument stream begins with the FIB wIdent (0xA5EC, LE).
	if len(wordDoc) < 2 || wordDoc[0] != 0xEC || wordDoc[1] != 0xA5 {
		t.Fatalf("decrypted WordDocument missing FIB magic; got % x", wordDoc[:min2(8, len(wordDoc))])
	}
}

// TestLegacyOfficeWrongPassword leaves the document locked when no candidate works.
func TestLegacyOfficeWrongPassword(t *testing.T) {
	data, err := os.ReadFile(fixturePath("rc4cryptoapi_password.xls"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("nope", "still-no"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	locked := false
	res.Root.Walk(func(n *Node) {
		if n.Status == StatusLocked {
			locked = true
		}
	})
	if !locked {
		t.Fatalf("expected a locked node; tree:\n%s", dumpTree(res.Root))
	}
}

func min2(a, b int) int {
	if a < b {
		return a
	}
	return b
}
