package xcrack

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestSharedFeederDeDup proves the shared feeder hands every candidate to
// exactly one puller even under heavy concurrency: the union of what the
// goroutines collect is the whole input, with no candidate delivered twice.
func TestSharedFeederDeDup(t *testing.T) {
	const n = 5000
	want := make([]string, n)
	for i := range want {
		want[i] = fmt.Sprintf("cand-%05d", i)
	}
	feeder := newSharedFeeder(candidates.Explicit(want...))

	var (
		mu   sync.Mutex
		seen = map[string]int{}
		got  int
	)
	var wg sync.WaitGroup
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				pw, err := feeder.Next()
				if err != nil {
					return
				}
				mu.Lock()
				seen[string(pw)]++
				got++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if got != n {
		t.Fatalf("pulled %d candidates, want %d", got, n)
	}
	for _, c := range want {
		if seen[c] != 1 {
			t.Fatalf("candidate %q delivered %d times, want exactly 1", c, seen[c])
		}
	}
}

// TestDualPipelineRecovers proves the dual CPU+GPU pipeline cracks a
// WinZip-AES entry end to end with the pure-Go stub accelerator, and that the
// device lane (not only the CPU) participated.
func TestDualPipelineRecovers(t *testing.T) {
	const password = "Welcome1"
	plain := bytes.Repeat([]byte("dual-pipeline-secret "), 64)
	for _, strength := range []byte{1, 3} { // AES-128 and AES-256
		data := buildWinZipAES(t, []byte(password), strength, "doc.bin", plain)
		// Put the password late so the bulk sweep (not a promoted/front guess) has
		// to find it, with plenty of wrong candidates ahead of it.
		cands := make([]string, 0, 300)
		for i := 0; i < 256; i++ {
			cands = append(cands, fmt.Sprintf("wrong-%03d", i))
		}
		cands = append(cands, password)

		stub := &stubAccel{}
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			candidates.Explicit(cands...), Options{Accelerator: stub, DualPipeline: true})
		if err != nil {
			t.Fatalf("strength %d: Process: %v", strength, err)
		}
		n := findDecrypted(res.Root)
		if n == nil || n.Password != password {
			t.Fatalf("strength %d: dual pipeline did not recover the password (node=%+v)", strength, n)
		}
		if stub.calls.Load() == 0 {
			t.Fatalf("strength %d: accelerator lane never dispatched in dual mode", strength)
		}
	}
}

// TestDualPipelineMatchesSequential proves the dual pipeline is a speed change,
// not a result change: it recovers the same password (and the same locked
// outcome for wrong-only candidates) as the default sequential accel path.
func TestDualPipelineMatchesSequential(t *testing.T) {
	const password = "Welcome1"
	data := buildWinZipAES(t, []byte(password), 3, "doc.bin", []byte("payload"))

	run := func(dual bool, cands ...string) *Node {
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			candidates.Explicit(cands...), Options{Accelerator: &stubAccel{}, DualPipeline: dual})
		if err != nil {
			t.Fatalf("Process(dual=%v): %v", dual, err)
		}
		return findDecrypted(res.Root)
	}

	// Hit case: same recovered password.
	seq := run(false, "a", "b", password)
	dual := run(true, "a", "b", password)
	if seq == nil || dual == nil || seq.Password != dual.Password {
		t.Fatalf("hit parity mismatch: seq=%+v dual=%+v", seq, dual)
	}

	// No-match case: both leave it locked (no false positive).
	for _, dualMode := range []bool{false, true} {
		res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
			candidates.Explicit("no1", "no2", "no3"), Options{Accelerator: &stubAccel{}, DualPipeline: dualMode})
		if err != nil {
			t.Fatalf("Process(no-match dual=%v): %v", dualMode, err)
		}
		if findDecrypted(res.Root) != nil {
			t.Fatalf("dual=%v: wrong-only candidates must not decrypt", dualMode)
		}
	}
}

// TestDualPipelineDeviceFailureFallsBack proves that when the accelerator cannot
// serve the parameters, the dual pipeline loses no candidate: the CPU lane still
// recovers the password that the (failed) device lane had pulled into a batch.
func TestDualPipelineDeviceFailureFallsBack(t *testing.T) {
	const password = "Welcome1"
	data := buildWinZipAES(t, []byte(password), 3, "doc.bin", []byte("payload"))

	// unsupported stub => every device derive reports ErrUnsupported, so each
	// batch is CPU-verified before the GPU lane stops.
	stub := &stubAccel{unsupported: true}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("x", "y", password, "z"), Options{Accelerator: stub, DualPipeline: true})
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	n := findDecrypted(res.Root)
	if n == nil || n.Password != password {
		t.Fatalf("dual pipeline lost the password on device failure (node=%+v)", n)
	}
}
