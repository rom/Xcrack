// Command impex-embed is a reference for embedding Xcrack the way the Impex
// malware scanner does: build one resource-bounded Pool at startup, then feed
// files through it, supplying per-scan candidate passwords in memory (e.g.
// harvested from an email body) alongside the built-in default list.
//
// Usage: impex-embed <file> [candidate-password ...]
package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrack/pkg/xcrack/candidates"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: impex-embed <file> [candidate-password ...]")
		os.Exit(2)
	}
	path := os.Args[1]
	emailPasswords := os.Args[2:] // pretend these came from the email body

	// Construct the Pool ONCE (at service startup). Its global semaphore keeps
	// total concurrent candidate testers <= MaxProcs no matter how many files
	// are processed concurrently by however many request goroutines.
	pool := xcrack.NewPool(xcrack.Options{
		Workers:  4,
		MaxProcs: 8,
		Budget:   xcrack.Budget{PerFile: 30 * time.Second},
		OnFound: func(f xcrack.Found) {
			// A weak/known password is itself a useful signal for the scanner.
			fmt.Printf("  [unlocked] %s with password %q\n", f.Path, f.Password)
		},
	})
	defer pool.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(2)
	}

	// Per-scan candidates: email-derived passwords first, then the built-in
	// malware-campaign default list.
	cands := candidates.Chain(
		candidates.Explicit(emailPasswords...),
		candidates.DefaultList(),
	)

	res, err := pool.Process(context.Background(), bytes.NewReader(data), int64(len(data)), cands)
	if err != nil {
		fmt.Fprintln(os.Stderr, "process:", err)
		os.Exit(2)
	}

	fmt.Printf("scanned %s: %d node(s), %d candidate(s) tried, %d byte(s) extracted in %s\n",
		path, res.Stats.FilesSeen, res.Stats.CandidatesTried, res.Stats.BytesExtracted, res.Stats.Elapsed)

	// Hand every leaf's decrypted content to the (stub) scanner.
	res.Root.Walk(func(n *xcrack.Node) {
		if n.Content == nil {
			if n.Status == xcrack.StatusLocked {
				fmt.Printf("  [LOCKED] %s -- could not decrypt; quarantine\n", n.Path)
			}
			return
		}
		rc, err := n.Content.Open()
		if err != nil {
			return
		}
		defer rc.Close()
		scanForMalware(n.Path, rc)
	})
}

// scanForMalware stands in for the real Impex analysis of decrypted bytes.
func scanForMalware(path string, r interface{ Read([]byte) (int, error) }) {
	buf := make([]byte, 64)
	n, _ := r.Read(buf)
	fmt.Printf("  [scan] %s: first %d bytes = %q...\n", path, n, buf[:n])
}
