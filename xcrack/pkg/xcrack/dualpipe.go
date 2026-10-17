package xcrack

import (
	"context"
	"io"
	"sync"

	"github.com/rom/xfileformats"
)

// sharedFeeder wraps a candidate source so the CPU search and the accelerator
// sweep of the dual pipeline can pull from ONE keyspace concurrently without
// ever testing a candidate twice: every Next is serialized behind a mutex and
// hands the candidate to exactly one caller (natural de-duplication /
// work-stealing). Reset is a no-op — the race must never rewind the shared
// stream mid-flight — and each returned slice is a fresh copy so a caller may
// hold it while the underlying source reuses its buffer.
type sharedFeeder struct {
	mu   sync.Mutex
	base CandidateSource
	done bool
}

func newSharedFeeder(base CandidateSource) *sharedFeeder {
	return &sharedFeeder{base: base}
}

func (s *sharedFeeder) Next() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return nil, io.EOF
	}
	pw, err := s.base.Next()
	if err != nil {
		s.done = true
		return nil, err
	}
	return append([]byte(nil), pw...), nil
}

// Reset is intentionally a no-op: a consumer (e.g. the CPU cracker) resets its
// source at the start, but the dual race must keep the single shared stream
// moving forward, never rewind it.
func (s *sharedFeeder) Reset() error { return nil }

func (s *sharedFeeder) Len() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.base.Len()
}

// crackDual runs the accelerator sweep and the CPU search concurrently over one
// shared, de-duplicated candidate stream — the dual CPU+GPU pipeline. The first
// side to find a password cancels the other; a no-match run exhausts the whole
// keyspace on both lanes. The device's apparent hits are always re-checked by
// ak.Finish on the CPU, so the accelerator never decides correctness, and if the
// device cannot serve these parameters mid-race it re-verifies its pending
// candidates on the CPU (nothing pulled from the shared stream goes untested)
// and leaves the rest of the sweep to the CPU lane. Promoted/hint/context
// guesses are tried by the caller before this, so the race covers only the
// general keyspace.
func (e *engine) crackDual(ctx context.Context, path string, verify func([]byte) (bool, error), ak *xfileformats.AccelKDF, depth int, acc *accounting, base CandidateSource) (string, bool) {
	if base == nil {
		return "", false
	}
	// Start the shared stream at the beginning once; the lanes never rewind it.
	if err := base.Reset(); err != nil {
		return e.crackCPU(ctx, path, verify, depth, acc, base)
	}
	feeder := newSharedFeeder(base)

	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		mu    sync.Mutex
		winPW string
		won   bool
	)
	record := func(pw string) {
		mu.Lock()
		if !won {
			won, winPW = true, pw
		}
		mu.Unlock()
		cancel() // stop the other lane
	}

	var wg sync.WaitGroup
	wg.Add(2)
	// GPU lane: the batched accelerator sweep.
	go func() {
		defer wg.Done()
		if pw, ok := e.gpuSweep(raceCtx, path, verify, ak, depth, acc, feeder); ok {
			record(pw)
		}
	}()
	// CPU lane: the normal concurrent search over the same shared feeder.
	go func() {
		defer wg.Done()
		if pw, ok := e.crackCPU(raceCtx, path, verify, depth, acc, feeder); ok {
			record(pw)
		}
	}()
	wg.Wait()

	if won {
		return winPW, true
	}
	return "", false
}

// crackCPU runs the engine's concurrent CPU search over src, applying FastReject
// as a cheap pre-check. It is the plain (non-accelerated) keyspace sweep, used
// directly when no accelerator is configured and as the CPU lane of crackDual.
func (e *engine) crackCPU(ctx context.Context, path string, verify func([]byte) (bool, error), depth int, acc *accounting, src CandidateSource) (string, bool) {
	if src == nil {
		return "", false
	}
	reject := e.opts.FastReject
	probe := func(pw []byte) (bool, error) {
		if reject != nil && reject(path, pw) {
			return false, nil // cheaply rejected: definitely not the password
		}
		return safeVerify(verify, pw)
	}
	pw, found, tried, err := e.cracker.Crack(ctx, probe, src)
	acc.addCandidates(tried)
	if e.opts.OnProgress != nil {
		e.opts.OnProgress(Progress{Path: path, CandidatesTried: acc.candidatesTried(), Depth: depth})
	}
	if err != nil || !found {
		return "", false
	}
	return string(pw), true
}

// gpuSweep pulls candidates from the shared feeder in batches, derives their
// keys on the accelerator, and tests each with ak.Finish (the authoritative CPU
// re-check). On a device error or unsupported parameters it re-verifies the
// pending batch on the CPU — so no candidate already pulled from the shared
// stream is lost — and returns, leaving the remaining keyspace to the CPU lane.
// It respects ctx cancellation (the other lane won, or the caller's deadline).
func (e *engine) gpuSweep(ctx context.Context, path string, verify func([]byte) (bool, error), ak *xfileformats.AccelKDF, depth int, acc *accounting, feeder *sharedFeeder) (string, bool) {
	if ak == nil || ak.Finish == nil {
		return "", false
	}
	reject := e.opts.FastReject
	maxCand := e.opts.Limits.MaxCandidates
	batchSize := e.accelBatchSize()
	batch := make([][]byte, 0, batchSize)

	// cpuVerifyBatch tests the pending batch on the CPU (used when the device
	// cannot serve these parameters mid-race, so nothing pulled goes untested).
	cpuVerifyBatch := func() (string, bool) {
		for _, pw := range batch {
			if ctx.Err() != nil {
				return "", false
			}
			if ok, err := safeVerify(verify, pw); err == nil && ok {
				return string(pw), true
			}
		}
		return "", false
	}

	// flush derives the pending batch on the device and tests each key. It
	// returns (hit, found, deviceFailed): deviceFailed signals the caller to stop
	// the GPU lane (after the batch was CPU-verified) and let the CPU lane finish.
	flush := func() (string, bool, bool) {
		if len(batch) == 0 {
			return "", false, false
		}
		dks, err := accelDerive(e.opts.Accelerator, ak, batch)
		if err != nil || len(dks) != len(batch) {
			hit, ok := cpuVerifyBatch()
			return hit, ok, true
		}
		acc.addCandidates(int64(len(batch)))
		for i, dk := range dks {
			if safeFinish(ak.Finish, dk, batch[i]) {
				return string(batch[i]), true, false
			}
		}
		if e.opts.OnProgress != nil {
			e.opts.OnProgress(Progress{Path: path, CandidatesTried: acc.candidatesTried(), Depth: depth})
		}
		batch = batch[:0]
		return "", false, false
	}

	for {
		if ctx.Err() != nil {
			return "", false
		}
		if maxCand > 0 && acc.candidatesTried() >= maxCand {
			return "", false
		}
		pw, nerr := feeder.Next()
		if nerr != nil { // io.EOF or a source error: test whatever remains, then stop
			hit, found, _ := flush()
			return hit, found
		}
		if reject != nil && reject(path, pw) {
			continue // cheaply rejected: never derive it
		}
		batch = append(batch, pw) // feeder already returns a private copy
		if len(batch) >= batchSize {
			hit, found, deviceFailed := flush()
			if found {
				return hit, true
			}
			if deviceFailed {
				return "", false // GPU lane stops; CPU lane sweeps the rest
			}
		}
	}
}
