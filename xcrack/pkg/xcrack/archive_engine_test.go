package xcrack

import (
	stdtar "archive/tar"
	"bytes"
	stdgzip "compress/gzip"
	"context"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestTarGzRecursion: gzip -> tar -> files, fully decomposed by the engine.
func TestTarGzRecursion(t *testing.T) {
	files := map[string][]byte{
		"docs/readme.txt": []byte("hello from the tarball"),
		"data/blob.bin":   bytes.Repeat([]byte("Q"), 2000),
	}
	var tb bytes.Buffer
	tw := stdtar.NewWriter(&tb)
	for name, content := range files {
		tw.WriteHeader(&stdtar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: stdtar.TypeReg})
		tw.Write(content)
	}
	tw.Close()

	var gb bytes.Buffer
	gw := stdgzip.NewWriter(&gb)
	gw.Name = "bundle.tar"
	gw.Write(tb.Bytes())
	gw.Close()

	res, err := Process(context.Background(), bytes.NewReader(gb.Bytes()), int64(gb.Len()),
		candidates.Explicit(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	if res.Root.Format != "gzip" {
		t.Fatalf("root format = %q, want gzip", res.Root.Format)
	}
	got := map[string][]byte{}
	res.Root.Walk(func(n *Node) {
		if n.Leaf() && n.Content != nil {
			rc, _ := n.Content.Open()
			b, _ := readAllRC(rc)
			got[n.Path] = b
		}
	})
	for name, want := range files {
		var match []byte
		for p, b := range got {
			if len(p) >= len(name) && p[len(p)-len(name):] == name {
				match = b
			}
		}
		if !bytes.Equal(match, want) {
			t.Errorf("file %s: content mismatch (tree:\n%s)", name, dumpTree(res.Root))
		}
	}
}
