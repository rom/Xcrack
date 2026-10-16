package xcrack

import (
	"bytes"
	"context"
	"os"
	"strings"
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

func TestWritePrometheus(t *testing.T) {
	m := Metrics{FilesProcessed: 3, CandidatesTried: 42, NodesDecrypted: 2, ProcessingNanos: 1_500_000_000}
	var b strings.Builder
	if _, err := m.WritePrometheus(&b); err != nil {
		t.Fatal(err)
	}
	s := b.String()
	for _, want := range []string{
		"# TYPE xcrack_files_processed_total counter",
		"xcrack_files_processed_total 3",
		"xcrack_candidates_tried_total 42",
		"xcrack_processing_seconds_total 1.5",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("Prometheus output missing %q:\n%s", want, s)
		}
	}
}

func TestOnAuditNoSecrets(t *testing.T) {
	data, err := os.ReadFile(fixturePath("rc4cryptoapi_password.doc"))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	var events []AuditEvent
	pool := NewPool(Options{OnAudit: func(e AuditEvent) { events = append(events, e) }})
	defer pool.Close()
	res, err := pool.Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("Password1234_"))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if len(events) == 0 {
		t.Fatal("no audit events emitted")
	}
	sawEncrypted := false
	for _, e := range events {
		if e.Encrypted {
			sawEncrypted = true
		}
	}
	if !sawEncrypted {
		t.Fatal("expected at least one encrypted node in the audit trail")
	}
	// AuditEvent has no password/content fields by construction (compile-time).
}
