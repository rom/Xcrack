package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats/formats/ooxml"
)

func TestLearnedSetOrdering(t *testing.T) {
	l := newLearnedSet(0)
	l.add("a")
	l.add("b")
	l.add("c")
	l.add("b") // b now has 2 hits
	l.add("b") // b now has 3
	l.add("c") // c now has 2
	// Expect b (3), c (2), a (1); ties keep insertion order.
	if got, want := l.snapshotOrdered(), []string{"b", "c", "a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ordered = %v, want %v", got, want)
	}
	if l.len() != 3 {
		t.Fatalf("len = %d, want 3", l.len())
	}
}

func TestLearnedSetBounded(t *testing.T) {
	l := newLearnedSet(2)
	l.add("a")
	l.add("b")
	l.add("c") // dropped: over the bound
	l.add("a") // existing key still counts
	if l.len() != 2 {
		t.Fatalf("len = %d, want 2 (bounded)", l.len())
	}
	if got := l.snapshotOrdered(); got[0] != "a" {
		t.Fatalf("ordered[0] = %q, want a (2 hits)", got[0])
	}
}

// encAgile builds a tiny agile-encrypted OOXML document for the given password.
func encAgile(t *testing.T, password, body string) []byte {
	t.Helper()
	var zb bytes.Buffer
	zw := stdzip.NewWriter(&zb)
	w, _ := zw.Create("word/document.xml")
	w.Write([]byte(body))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := ooxml.BuildEncryptedAgile([]byte(password), zb.Bytes(), 100)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// TestCorpusPromotionCrossesFiles proves corpus-wide promotion: a password
// recovered from the first file is tried on a second file whose own candidate
// source does NOT contain it. With CorpusPromotion the second file unlocks;
// without it, the same second file stays locked (the control).
func TestCorpusPromotionCrossesFiles(t *testing.T) {
	const pw = "ReUsed-Pw-2026"
	fileA := encAgile(t, pw, "<w:document>A</w:document>")
	fileB := encAgile(t, pw, "<w:document>B</w:document>")

	// B's own candidates never include pw; only corpus promotion can unlock it.
	srcA := func() CandidateSource { return candidates.Explicit("wrong", pw) }
	srcB := func() CandidateSource { return candidates.Explicit("nope", "nada") }

	t.Run("enabled unlocks B", func(t *testing.T) {
		pool := NewPool(Options{CorpusPromotion: true})
		defer pool.Close()
		ra, _ := pool.Process(context.Background(), bytes.NewReader(fileA), int64(len(fileA)), srcA())
		if ra.Root.Password != pw || ra.Root.Status != StatusDecrypted {
			t.Fatalf("file A should have cracked: status=%v pw=%q", ra.Root.Status, ra.Root.Password)
		}
		rb, _ := pool.Process(context.Background(), bytes.NewReader(fileB), int64(len(fileB)), srcB())
		if rb.Root.Status != StatusDecrypted || rb.Root.Password != pw {
			t.Fatalf("file B should have cracked via corpus promotion: status=%v pw=%q", rb.Root.Status, rb.Root.Password)
		}
		if pool.learned.len() == 0 {
			t.Fatal("learned set should hold the recovered password")
		}
	})

	t.Run("disabled leaves B locked", func(t *testing.T) {
		pool := NewPool(Options{}) // CorpusPromotion off
		defer pool.Close()
		ra, _ := pool.Process(context.Background(), bytes.NewReader(fileA), int64(len(fileA)), srcA())
		if ra.Root.Status != StatusDecrypted {
			t.Fatalf("file A should still crack from its own candidates: %v", ra.Root.Status)
		}
		rb, _ := pool.Process(context.Background(), bytes.NewReader(fileB), int64(len(fileB)), srcB())
		if rb.Root.Status != StatusLocked {
			t.Fatalf("file B must stay locked without corpus promotion: status=%v pw=%q", rb.Root.Status, rb.Root.Password)
		}
	})
}
