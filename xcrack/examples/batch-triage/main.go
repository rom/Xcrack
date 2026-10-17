// Command batch-triage embeds Xcrack as a concurrent triage service: one
// resource-bounded Pool is built once and many files are pushed through it in
// parallel, exactly as a malware scanner or a DLP appliance would. It shows the
// production embedding shape — a shared Pool, a bounded worker fan-out, an audit
// hook, and an aggregate Metrics summary — and emits a machine-readable JSON
// line per file plus a run summary.
//
// Usage:
//
//	batch-triage [-jobs N] [-timeout DUR] [-defaults] <file> [file ...]
//
// Candidates here are the built-in common-password list (optional) plus a tiny
// in-memory set; a real deployment would plug in its own CandidateProvider.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

func main() {
	jobs := flag.Int("jobs", 4, "files processed concurrently")
	timeout := flag.Duration("timeout", 30*time.Second, "per-file time budget")
	useDefaults := flag.Bool("defaults", true, "also try the built-in common-password list")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: batch-triage [-jobs N] [-timeout DUR] [-defaults] <file> ...")
		os.Exit(2)
	}

	// Build the Pool ONCE. Its global semaphore bounds total concurrent candidate
	// testers to MaxProcs regardless of how many files are in flight, so the
	// service degrades gracefully under load instead of oversubscribing the CPU.
	pool := xcrack.NewPool(xcrack.Options{
		MaxProcs: 8,
		Budget:   xcrack.Budget{PerFile: *timeout},
		OnFound: func(f xcrack.Found) {
			fmt.Printf("  [unlocked] %s\n", f.Path) // never log the password itself
		},
	})
	defer pool.Close()

	// A shared candidate set every file is tried against. Explicit() returns a
	// fresh independent cursor each call, so concurrent Process calls do not share
	// iterator state.
	newCandidates := func() xcrack.CandidateSource {
		base := candidates.Explicit("letmein", "Password1", "Welcome1", "secret")
		if *useDefaults {
			return candidates.Chain(base, candidates.DefaultList())
		}
		return base
	}

	type outcome struct {
		File      string   `json:"file"`
		Cracked   bool     `json:"cracked"`
		Passwords []string `json:"passwords,omitempty"`
		Err       string   `json:"error,omitempty"`
	}

	var (
		wg   sync.WaitGroup
		sem  = make(chan struct{}, *jobs)
		mu   sync.Mutex
		done int
	)
	enc := json.NewEncoder(os.Stdout)
	for _, path := range flag.Args() {
		wg.Add(1)
		sem <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-sem }()

			data, err := os.ReadFile(path)
			o := outcome{File: filepath.Base(path)}
			if err != nil {
				o.Err = err.Error()
			} else if res, perr := pool.Process(context.Background(), bytes.NewReader(data), int64(len(data)), newCandidates()); perr != nil {
				o.Err = perr.Error()
			} else {
				o.Passwords = res.Passwords()
				o.Cracked = len(o.Passwords) > 0
				res.Close()
			}
			mu.Lock()
			_ = enc.Encode(o) // one JSON object per line
			done++
			mu.Unlock()
		}(path)
	}
	wg.Wait()

	// Aggregate counters for the whole run (counts only, no secrets).
	m := pool.Metrics()
	fmt.Fprintf(os.Stderr, "\ntriaged %d file(s): %d nodes seen, %d decrypted, %d locked, %d candidates tried in %s\n",
		done, m.NodesTotal, m.NodesDecrypted, m.NodesLocked, m.CandidatesTried,
		time.Duration(m.ProcessingNanos).Round(time.Millisecond))
}
