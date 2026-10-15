package xcrack

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestCandidateProviderAndMetrics verifies the pluggable provider supplies the
// winning password (the per-call source is nil) and that Pool metrics tally.
func TestCandidateProviderAndMetrics(t *testing.T) {
	data, err := os.ReadFile(fixturePath("rc4cryptoapi_password.doc"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	pool := NewPool(Options{
		CandidateProvider: CandidateProviderFunc(func(context.Context) CandidateSource {
			return candidates.Explicit("nope", "Password1234_")
		}),
	})
	defer pool.Close()

	res, err := pool.Process(context.Background(), bytes.NewReader(data), int64(len(data)), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	found := false
	for _, p := range res.Passwords() {
		if p == "Password1234_" {
			found = true
		}
	}
	if !found {
		t.Fatalf("provider did not supply the winning password; got %v", res.Passwords())
	}

	m := pool.Metrics()
	if m.FilesProcessed != 1 {
		t.Errorf("FilesProcessed = %d, want 1", m.FilesProcessed)
	}
	if m.NodesDecrypted < 1 {
		t.Errorf("NodesDecrypted = %d, want >= 1", m.NodesDecrypted)
	}
	if m.CandidatesTried < 1 {
		t.Errorf("CandidatesTried = %d, want >= 1", m.CandidatesTried)
	}
	if m.ProcessingNanos <= 0 {
		t.Errorf("ProcessingNanos = %d, want > 0", m.ProcessingNanos)
	}

	// A second call accumulates.
	res2, _ := pool.Process(context.Background(), bytes.NewReader(data), int64(len(data)), nil)
	defer res2.Close()
	if got := pool.Metrics().FilesProcessed; got != 2 {
		t.Errorf("FilesProcessed after 2 calls = %d, want 2", got)
	}
}
