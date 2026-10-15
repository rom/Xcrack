package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestDiskSpill forces a tiny spill threshold and verifies spilled leaf content
// still reads back correctly and Close() releases it.
func TestDiskSpill(t *testing.T) {
	content := bytes.Repeat([]byte("spill-me-"), 500) // ~4.5 KiB
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	w, _ := zw.Create("big.txt")
	w.Write(content)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	res, err := Process(context.Background(), bytes.NewReader(b.Bytes()), int64(b.Len()),
		candidates.Explicit(), Options{Limits: Limits{SpillThreshold: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	leaf := findLeaf(res.Root, "big.txt")
	if leaf == nil {
		t.Fatalf("leaf not found; tree:\n%s", dumpTree(res.Root))
	}
	if _, ok := leaf.Content.(*spillContent); !ok {
		t.Fatalf("expected spillContent for %d-byte leaf, got %T", leaf.Content.Size(), leaf.Content)
	}
	rc, err := leaf.Content.Open()
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, rc)
	rc.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("spilled content mismatch: %d vs %d bytes", len(got), len(content))
	}
	if err := res.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func readAll(t *testing.T, r interface{ Read([]byte) (int, error) }) []byte {
	t.Helper()
	b, err := readAllRC(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
