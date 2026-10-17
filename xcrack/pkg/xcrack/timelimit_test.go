package xcrack

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/rom/xcrypto/candidates"
)

// TestPerFileDeadlineLocksNotErrors proves the per-file time budget
// (--time-limit / Budget.PerFile) makes a stuck search give up gracefully: the
// node comes back Locked, never StatusError, so a batch run keeps going and the
// exit status is "couldn't crack" (1) rather than "failed" (2).
func TestPerFileDeadlineLocksNotErrors(t *testing.T) {
	data := buildWinZipAES(t, []byte("Welcome1"), 3, "doc.bin", []byte("x"))
	// A one-nanosecond per-file budget: the deadline fires before the search can
	// run, exercising the engine's deadline-exceeded path.
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong1", "wrong2"), Options{Budget: Budget{PerFile: time.Nanosecond}})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	res.Root.Walk(func(n *Node) {
		if n.Status == StatusError {
			t.Fatalf("deadline produced StatusError (%v); want a graceful give-up", n.Err)
		}
	})
	if res.Root.Status != StatusLocked {
		t.Fatalf("root status = %v, want locked", res.Root.Status)
	}
}
