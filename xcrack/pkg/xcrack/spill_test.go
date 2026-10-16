package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats/formats/ooxml"
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
	sc, ok := leaf.Content.(*source)
	if !ok || sc.f == nil {
		t.Fatalf("expected a file-backed source for %d-byte leaf, got %T", leaf.Content.Size(), leaf.Content)
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

// TestDiskSpillEncrypted exercises the streaming decrypt path: an encrypted
// OOXML whose decrypted inner ZIP (and the entry within) exceed the spill
// threshold must stream to disk — the leaf is a file-backed source — and still
// read back byte-for-byte, proving the decrypt→materialize pipeline never
// depends on holding the whole payload in memory.
func TestDiskSpillEncrypted(t *testing.T) {
	content := bytes.Repeat([]byte("encrypted-and-spilled-"), 400) // ~8.8 KiB
	var zb bytes.Buffer
	zw := stdzip.NewWriter(&zb)
	w, _ := zw.Create("inner/big.txt")
	w.Write(content)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	const pw = "Spill-Secret-1"
	enc, err := ooxml.BuildEncryptedAgile([]byte(pw), zb.Bytes(), 100)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Process(context.Background(), bytes.NewReader(enc), int64(len(enc)),
		candidates.Explicit("wrong", pw), Options{Limits: Limits{SpillThreshold: 1024}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	if res.Root.Status != StatusDecrypted || res.Root.Password != pw {
		t.Fatalf("root not decrypted: status=%v pw=%q", res.Root.Status, res.Root.Password)
	}
	leaf := findLeaf(res.Root, "big.txt")
	if leaf == nil {
		t.Fatalf("leaf not found; tree:\n%s", dumpTree(res.Root))
	}
	sc, ok := leaf.Content.(*source)
	if !ok || sc.f == nil {
		t.Fatalf("expected a file-backed source for the %d-byte decrypted leaf, got %T", leaf.Content.Size(), leaf.Content)
	}
	rc, err := leaf.Content.Open()
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, rc)
	rc.Close()
	if !bytes.Equal(got, content) {
		t.Fatalf("decrypted spilled content mismatch: %d vs %d bytes", len(got), len(content))
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
