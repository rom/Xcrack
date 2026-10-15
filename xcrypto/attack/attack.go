// Package attack is the crypto/cracking engine: given a Probe (a single-password
// test for some Challenge) and a candidate Source, it searches for a password
// that satisfies the probe, concurrently and within a global resource bound.
//
// It is deliberately free of any file-format or recursion knowledge: a probe is
// just a func(password) (bool, error). Any tool can build a probe from an
// xcrypto scheme and reuse this engine. An Engine holds one global semaphore, so
// an embedder can construct it once and bound the total number of concurrent
// password testers across every Crack call.
package attack

import (
	"context"
	"sync"
	"sync/atomic"
)

// Source yields password candidates. It need not be safe for concurrent use;
// the engine serializes access behind a feeder. (This matches
// github.com/rom/xcrypto/candidates.Source structurally.)
type Source interface {
	Next() ([]byte, error)
	Len() int64
	Reset() error
}

// Probe tests a single password against some fixed Challenge. It must be safe
// for concurrent use and authoritative (no false positives) so a reported hit
// is real.
type Probe func(password []byte) (ok bool, err error)

// Options configures an Engine.
type Options struct {
	Workers       int   // concurrent testers per Crack call (0 => 1)
	MaxProcs      int   // global ceiling on concurrent testers (0 => Workers)
	MaxCandidates int64 // cap per Crack call (0 => unlimited)
	// OnProgress, if set, is called periodically with the running count tried.
	OnProgress func(tried int64)
}

// Engine runs password searches under a shared global semaphore.
type Engine struct {
	workers  int
	maxCand  int64
	progress func(int64)
	sem      chan struct{}
}

// New returns an Engine. The global semaphore is sized from MaxProcs (at least
// Workers, at least 1).
func New(o Options) *Engine {
	w := o.Workers
	if w < 1 {
		w = 1
	}
	mp := o.MaxProcs
	if mp < w {
		mp = w
	}
	return &Engine{
		workers:  w,
		maxCand:  o.MaxCandidates,
		progress: o.OnProgress,
		sem:      make(chan struct{}, mp),
	}
}

// Workers reports the per-call worker count.
func (e *Engine) Workers() int { return e.workers }

func (e *Engine) acquire(ctx context.Context) error {
	select {
	case e.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Engine) release() { <-e.sem }

// Crack searches src for a password satisfying probe. It returns the winning
// password (nil if none), whether one was found, and the number of candidates
// tested. It stops at the first match.
func (e *Engine) Crack(ctx context.Context, probe Probe, src Source) (password []byte, found bool, tried int64, err error) {
	if src == nil {
		return nil, false, 0, nil
	}
	if rerr := src.Reset(); rerr != nil {
		return nil, false, 0, rerr
	}

	sctx, cancel := context.WithCancel(ctx)
	defer cancel()

	feed := make(chan []byte, e.workers*2)
	var triedN atomic.Int64

	var (
		once   sync.Once
		result []byte
		hit    bool
		perr   error
		wg     sync.WaitGroup
	)

	// feeder (in the WaitGroup so it stops touching src before Crack returns)
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(feed)
		for {
			if sctx.Err() != nil {
				return
			}
			pw, nerr := src.Next()
			if nerr != nil {
				return
			}
			if e.maxCand > 0 && triedN.Load() >= e.maxCand {
				return
			}
			select {
			case feed <- pw:
			case <-sctx.Done():
				return
			}
		}
	}()

	for w := 0; w < e.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.acquire(sctx) != nil {
				return
			}
			defer e.release()
			for pw := range feed {
				if sctx.Err() != nil {
					return
				}
				n := triedN.Add(1)
				if e.progress != nil && n%4096 == 0 {
					e.progress(n)
				}
				ok, verr := probe(pw)
				if verr != nil {
					once.Do(func() { perr = verr; cancel() })
					return
				}
				if ok {
					once.Do(func() {
						result = append([]byte(nil), pw...)
						hit = true
						cancel()
					})
					return
				}
			}
		}()
	}
	wg.Wait()
	return result, hit, triedN.Load(), perr
}
