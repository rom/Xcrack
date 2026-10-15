// Package xcrack is the recovery engine: given an untrusted (possibly nested,
// possibly encrypted) file and a set of candidate passwords, it produces a
// verified tree of decrypted/extracted content plus the passwords that unlocked
// each layer -- safely and within bounded resources. It is library-first: the
// Xcrack CLI is a thin wrapper, and embedders (such as the Impex scanner)
// construct a Pool once and feed files through it.
package xcrack

import (
	"context"
	"io"
	"time"

	"github.com/rom/xcrypto/attack"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/formats/ooxml"
	"github.com/rom/xfileformats/formats/zip"
)

// CandidateSource yields password candidates. It is an alias for the shared
// candidates.Source so sources from the xcrypto candidates package (and the
// pattern engine) are accepted directly. Implementations need not be
// thread-safe; the engine serializes access behind a feeder.
type CandidateSource = candidates.Source

// Logger is a minimal structured logger. The engine never logs recovered
// passwords or decrypted content through it.
type Logger interface {
	Debugf(format string, args ...any)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Debugf(string, ...any) {}
func (nopLogger) Infof(string, ...any)  {}
func (nopLogger) Warnf(string, ...any)  {}
func (nopLogger) Errorf(string, ...any) {}

// Progress is reported via Options.OnProgress during a search.
type Progress struct {
	Path            string
	CandidatesTried int64
	Depth           int
	BytesExtracted  int64
}

// Found is reported via Options.OnFound when a candidate unlocks a node. The
// password is delivered to the caller here; it is never written to the Logger.
type Found struct {
	Path     string
	Format   string
	Password string
}

// Options configures an engine/Pool. Every CLI flag maps to a field here, so
// the library and CLI have identical capability (CON-3).
type Options struct {
	Workers         int // candidate-test goroutines within one file (0 => NumCPU)
	FileConcurrency int // reserved for sibling-entry parallelism (phase 2)
	MaxProcs        int // global ceiling on concurrent candidate testers (0 => NumCPU)

	// Behavior toggles are phrased so the zero value is the sensible default:
	// the engine recurses, promotes passwords, and stops on the first match
	// unless told otherwise.
	NoRecurse        bool // disable container decomposition (default: recurse)
	NoPromote        bool // disable password promotion (default: promote)
	FindAll          bool // reserved: keep searching after the first match (phase 2)
	ExplodeDocuments bool // decompose documents into parts (default false, opt-in)

	Limits Limits
	Budget Budget

	// Registry selects which formats are enabled. nil => DefaultRegistry().
	Registry *xfileformats.Registry

	OnProgress func(Progress)
	OnFound    func(Found)
	Logger     Logger
}

// DefaultOptions returns Options with explicit, conservative defaults. The zero
// Options value already behaves the same way (recurse, promote, stop-on-first,
// NumCPU workers); DefaultOptions is provided for discoverability and as a base
// to tweak.
func DefaultOptions() Options {
	return Options{
		Workers:  numCPU(),
		MaxProcs: numCPU(),
		Limits:   DefaultLimits(),
	}
}

// DefaultRegistry returns a registry with the built-in, safe set of formats.
func DefaultRegistry() *xfileformats.Registry {
	r := xfileformats.NewRegistry()
	zip.Register(r)
	ooxml.Register(r)
	return r
}

func (o *Options) normalize() {
	o.Workers = clampPositive(o.Workers, numCPU())
	o.MaxProcs = clampPositive(o.MaxProcs, numCPU())
	o.FileConcurrency = clampPositive(o.FileConcurrency, numCPU())
	if o.Workers > o.MaxProcs {
		o.Workers = o.MaxProcs
	}
	// Apply safety floors to limits: a caller may relax, but not disable, the
	// bomb defenses below a floor.
	def := DefaultLimits()
	if o.Limits.MaxDepth <= 0 || o.Limits.MaxDepth > 4096 {
		o.Limits.MaxDepth = def.MaxDepth
	}
	if o.Limits.MaxTotalBytes <= 0 {
		o.Limits.MaxTotalBytes = def.MaxTotalBytes
	}
	if o.Limits.MaxNodes <= 0 {
		o.Limits.MaxNodes = def.MaxNodes
	}
	if o.Limits.MaxEntrySize <= 0 {
		o.Limits.MaxEntrySize = def.MaxEntrySize
	}
	if o.Registry == nil {
		o.Registry = DefaultRegistry()
	}
	if o.Logger == nil {
		o.Logger = nopLogger{}
	}
}

// Pool is a reusable, resource-bounded engine. Construct it once (e.g. at
// service startup) and call Process concurrently from many goroutines; the
// global semaphore keeps the total number of live candidate testers at or below
// MaxProcs regardless of how many files are in flight.
type Pool struct {
	opts    Options
	cracker *attack.Engine
}

// NewPool returns a Pool configured by opts (defaults applied). The cracking
// engine's global semaphore keeps the total number of live candidate testers at
// or below MaxProcs across every concurrent Process call.
func NewPool(opts Options) *Pool {
	opts.normalize()
	cr := attack.New(attack.Options{
		Workers:       opts.Workers,
		MaxProcs:      opts.MaxProcs,
		MaxCandidates: opts.Limits.MaxCandidates,
	})
	return &Pool{opts: opts, cracker: cr}
}

// Close releases the Pool. It is currently a no-op but is part of the stable
// API so callers can adopt it now.
func (p *Pool) Close() error { return nil }

// Process decrypts and recursively decomposes src, returning the result tree.
// src must remain readable for the duration of the call. It is safe to call
// concurrently.
func (p *Pool) Process(ctx context.Context, src io.ReaderAt, size int64, candidates CandidateSource) (*Result, error) {
	start := time.Now()
	// Honor the whole-run deadline and the per-file budget; for a single
	// Process call the tighter of the two bounds applies.
	if d := tighter(p.opts.Budget.Total, p.opts.Budget.PerFile); d > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d)
		defer cancel()
	}
	e := &engine{opts: p.opts, cracker: p.cracker}
	data, err := readAllAt(src, size, p.opts.Limits.MaxEntrySize)
	if err != nil {
		return nil, err
	}
	acc := newAccounting(p.opts.Limits)
	var promoted []string
	root := e.decompose(ctx, "", data, 0, nil, &promoted, acc, candidates)
	stats := acc.snapshot()
	stats.Elapsed = time.Since(start)
	return &Result{Root: root, Stats: stats}, nil
}

// Process is the one-shot convenience entry point: it builds a single-use Pool,
// processes src, and returns the result.
func Process(ctx context.Context, src io.ReaderAt, size int64, candidates CandidateSource, opts Options) (*Result, error) {
	p := NewPool(opts)
	defer p.Close()
	return p.Process(ctx, src, size, candidates)
}

// readAllAt reads up to max+1 bytes from an io.ReaderAt so oversize can be
// detected, then returns exactly the content or an error if it exceeds max.
func readAllAt(src io.ReaderAt, size, max int64) ([]byte, error) {
	if size < 0 {
		size = 0
	}
	limit := size
	if max > 0 && limit > max {
		limit = max
	}
	buf := make([]byte, limit)
	n, err := io.ReadFull(io.NewSectionReader(src, 0, limit), buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// tighter returns the smaller positive duration of a and b (0 means "no bound").
func tighter(a, b time.Duration) time.Duration {
	switch {
	case a <= 0:
		return b
	case b <= 0:
		return a
	case a < b:
		return a
	default:
		return b
	}
}
