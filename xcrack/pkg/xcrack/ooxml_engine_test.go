package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats/formats/ooxml"
)

// TestEncryptedOOXMLRecursion exercises the whole-file Encrypted path: an
// agile-encrypted Office document decrypts to a ZIP, which the engine
// re-detects and decomposes into its entries.
func TestEncryptedOOXMLRecursion(t *testing.T) {
	// inner OOXML package: a plaintext ZIP with one document part
	var zb bytes.Buffer
	zw := stdzip.NewWriter(&zb)
	w, _ := zw.Create("word/document.xml")
	docContent := []byte("<w:document>the analysable body</w:document>")
	w.Write(docContent)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	password := "Secret2024"
	data, err := ooxml.BuildEncryptedAgile([]byte(password), zb.Bytes(), 100)
	if err != nil {
		t.Fatal(err)
	}

	src := candidates.Explicit("wrong", password)
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)), src, Options{})
	if err != nil {
		t.Fatal(err)
	}

	root := res.Root
	if root.Format != "ooxml" {
		t.Fatalf("root format = %q, want ooxml", root.Format)
	}
	if !root.WasEncrypted || root.Password != password || root.Status != StatusDecrypted {
		t.Fatalf("root: encrypted=%v password=%q status=%v", root.WasEncrypted, root.Password, root.Status)
	}
	if len(root.Children) == 0 {
		t.Fatalf("expected the decrypted ZIP's entries as children; tree:\n%s", dumpTree(root))
	}

	var leaf *Node
	root.Walk(func(n *Node) {
		if leaf == nil && n.Leaf() && n.Content != nil {
			leaf = n
		}
	})
	if leaf == nil {
		t.Fatalf("no leaf content; tree:\n%s", dumpTree(root))
	}
	rc, _ := leaf.Content.Open()
	got, _ := readAllRC(rc)
	if !bytes.Equal(got, docContent) {
		t.Fatalf("leaf content mismatch:\n got %q\nwant %q", got, docContent)
	}
	found := false
	for _, p := range res.Passwords() {
		if p == password {
			found = true
		}
	}
	if !found {
		t.Errorf("Passwords() = %v, want to include %q", res.Passwords(), password)
	}
}
