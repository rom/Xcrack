package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"testing"

	"github.com/rom/xcrypto/attack"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats"
)

// zipBomb builds a ZIP whose single entry decompresses to `uncompressed` bytes
// of zeros but stores only a tiny deflate stream.
func zipBomb(t *testing.T, uncompressed int) []byte {
	t.Helper()
	var comp bytes.Buffer
	fw, _ := flate.NewWriter(&comp, flate.BestCompression)
	chunk := make([]byte, 1<<16)
	crc := crc32.NewIEEE()
	for rem := uncompressed; rem > 0; {
		n := len(chunk)
		if n > rem {
			n = rem
		}
		fw.Write(chunk[:n])
		crc.Write(chunk[:n])
		rem -= n
	}
	fw.Close()
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	fh := &stdzip.FileHeader{Name: "bomb.bin", Method: stdzip.Deflate}
	fh.CRC32 = crc.Sum32()
	fh.UncompressedSize64 = uint64(uncompressed)
	fh.CompressedSize64 = uint64(comp.Len())
	w, _ := zw.CreateRaw(fh)
	w.Write(comp.Bytes())
	zw.Close()
	return b.Bytes()
}

// TestZipBomb: a 200 MiB-expanding entry must be cut off at MaxEntrySize and
// never fully materialized.
func TestZipBomb(t *testing.T) {
	data := zipBomb(t, 200<<20)
	if len(data) > 1<<20 {
		t.Fatalf("bomb fixture unexpectedly large: %d bytes", len(data))
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit(), Options{Limits: Limits{MaxEntrySize: 1 << 20}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	var limited bool
	res.Root.Walk(func(n *Node) {
		if n.Status == StatusError && errors.Is(n.Err, xfileformats.ErrLimitExceeded) {
			limited = true
		}
	})
	if !limited {
		t.Fatalf("expected an entry-size limit on the bomb; tree:\n%s", dumpTree(res.Root))
	}
	if res.Stats.BytesExtracted > 4<<20 {
		t.Fatalf("extracted %d bytes; the bomb was not bounded", res.Stats.BytesExtracted)
	}
}

// TestFanOutBomb: a huge entry count is bounded by MaxNodes.
func TestFanOutBomb(t *testing.T) {
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	for i := 0; i < 500; i++ {
		w, _ := zw.Create(fmt.Sprintf("f%d.txt", i))
		w.Write([]byte("x"))
	}
	zw.Close()

	res, err := Process(context.Background(), bytes.NewReader(b.Bytes()), int64(b.Len()),
		candidates.Explicit(), Options{Limits: Limits{MaxNodes: 10}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Stats.FilesSeen > 10 {
		t.Fatalf("FilesSeen = %d, want <= MaxNodes (10)", res.Stats.FilesSeen)
	}
	var sawLimit bool
	res.Root.Walk(func(n *Node) {
		if n.Status == StatusLimitExceeded {
			sawLimit = true
		}
	})
	if !sawLimit {
		t.Fatal("expected node-count limit to fire")
	}
}

// TestTotalBytesBudget: the cumulative decompressed budget bounds a tree of
// otherwise-acceptable entries.
func TestTotalBytesBudget(t *testing.T) {
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	for i := 0; i < 8; i++ {
		w, _ := zw.Create(fmt.Sprintf("r%d.bin", i))
		buf := make([]byte, 50<<10)
		rand.Read(buf) // incompressible
		w.Write(buf)
	}
	zw.Close()

	res, err := Process(context.Background(), bytes.NewReader(b.Bytes()), int64(b.Len()),
		candidates.Explicit(), Options{Limits: Limits{MaxTotalBytes: 600 << 10, MaxEntrySize: 1 << 20, MaxNodes: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Stats.BytesExtracted > 600<<10 {
		t.Fatalf("extracted %d bytes, over the 600 KiB budget", res.Stats.BytesExtracted)
	}
	var sawLimit bool
	res.Root.Walk(func(n *Node) {
		if n.Status == StatusLimitExceeded {
			sawLimit = true
		}
	})
	if !sawLimit {
		t.Fatal("expected the total-bytes budget to fire")
	}
}

// TestCycleDetection: content appearing as its own ancestor (a quine-like loop)
// is pruned.
func TestCycleDetection(t *testing.T) {
	opts := Options{}
	opts.normalize()
	e := &engine{
		opts:    opts,
		cracker: attack.New(attack.Options{Workers: 1, MaxProcs: 1}),
		spill:   newSpillSet(0, ""),
	}
	acc := newAccounting(opts.Limits)
	data := []byte("content that is registered as its own ancestor")
	ancestors := [][32]byte{sha256.Sum256(data)}
	n := e.decompose(context.Background(), "x", data, 1, ancestors, newPromoter(true, nil), acc, candidates.Explicit(), nil)
	if n.Status != StatusLimitExceeded {
		t.Fatalf("cycle not detected: status = %v", n.Status)
	}
}
