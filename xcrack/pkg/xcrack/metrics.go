package xcrack

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/rom/xcrypto/candidates"
)

// chainSources returns a source that yields a's candidates before b's. A nil
// operand is treated as empty.
func chainSources(a, b CandidateSource) CandidateSource {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	default:
		return candidates.Chain(a, b)
	}
}

// Metrics is a point-in-time snapshot of a Pool's aggregate counters across
// every Process call it has served. It carries only counts and durations --
// never passwords or content -- so it is safe to expose for telemetry (e.g. a
// /metrics endpoint or a Prometheus bridge).
type Metrics struct {
	FilesProcessed   int64 `json:"files_processed"`
	CandidatesTried  int64 `json:"candidates_tried"`
	BytesExtracted   int64 `json:"bytes_extracted"`
	NodesTotal       int64 `json:"nodes_total"`
	NodesDecrypted   int64 `json:"nodes_decrypted"`
	NodesLocked      int64 `json:"nodes_locked"`
	NodesError       int64 `json:"nodes_error"`
	LimitHits        int64 `json:"limit_hits"`
	ProcessingNanos  int64 `json:"processing_nanos"`
	ProcessingErrors int64 `json:"processing_errors"`
}

// metrics holds the live atomic counters behind a Pool.
type metrics struct {
	filesProcessed   atomic.Int64
	candidatesTried  atomic.Int64
	bytesExtracted   atomic.Int64
	nodesTotal       atomic.Int64
	nodesDecrypted   atomic.Int64
	nodesLocked      atomic.Int64
	nodesError       atomic.Int64
	limitHits        atomic.Int64
	processingNanos  atomic.Int64
	processingErrors atomic.Int64
}

// record folds one completed Process call into the aggregate counters.
func (m *metrics) record(res *Result, elapsed time.Duration) {
	m.filesProcessed.Add(1)
	m.processingNanos.Add(int64(elapsed))
	if res == nil {
		return
	}
	m.candidatesTried.Add(res.Stats.CandidatesTried)
	m.bytesExtracted.Add(res.Stats.BytesExtracted)
	m.limitHits.Add(int64(res.Stats.LimitHits))
	if res.Root != nil {
		res.Root.Walk(func(n *Node) {
			m.nodesTotal.Add(1)
			switch n.Status {
			case StatusDecrypted:
				m.nodesDecrypted.Add(1)
			case StatusLocked:
				m.nodesLocked.Add(1)
			case StatusError:
				m.nodesError.Add(1)
			}
		})
	}
}

func (m *metrics) snapshot() Metrics {
	return Metrics{
		FilesProcessed:   m.filesProcessed.Load(),
		CandidatesTried:  m.candidatesTried.Load(),
		BytesExtracted:   m.bytesExtracted.Load(),
		NodesTotal:       m.nodesTotal.Load(),
		NodesDecrypted:   m.nodesDecrypted.Load(),
		NodesLocked:      m.nodesLocked.Load(),
		NodesError:       m.nodesError.Load(),
		LimitHits:        m.limitHits.Load(),
		ProcessingNanos:  m.processingNanos.Load(),
		ProcessingErrors: m.processingErrors.Load(),
	}
}

// Metrics returns the Pool's aggregate counters. Safe to call concurrently.
func (p *Pool) Metrics() Metrics { return p.metrics.snapshot() }

// CandidateProvider supplies candidates for a Process call. It lets an embedder
// (or the HTTP service) plug in a live source -- e.g. per-scan passwords pulled
// from request context, or an org-wide list refreshed out of band -- once at
// Pool construction, instead of threading a source through every call site. The
// provider's source is tried ahead of the per-call source. Returning nil means
// "no extra candidates" for this call.
type CandidateProvider interface {
	Candidates(ctx context.Context) CandidateSource
}

// CandidateProviderFunc adapts a function to CandidateProvider.
type CandidateProviderFunc func(ctx context.Context) CandidateSource

// Candidates implements CandidateProvider.
func (f CandidateProviderFunc) Candidates(ctx context.Context) CandidateSource { return f(ctx) }
