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
	"strings"
	"time"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrypto/attack"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/scheme/zipcrypto"
	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/formats/access"
	"github.com/rom/xfileformats/formats/age"
	"github.com/rom/xfileformats/formats/archive"
	fdmg "github.com/rom/xfileformats/formats/dmg"
	"github.com/rom/xfileformats/formats/ethwallet"
	"github.com/rom/xfileformats/formats/iwork"
	"github.com/rom/xfileformats/formats/jks"
	"github.com/rom/xfileformats/formats/keepass"
	"github.com/rom/xfileformats/formats/msoffice"
	"github.com/rom/xfileformats/formats/odf"
	"github.com/rom/xfileformats/formats/ooxml"
	fp12 "github.com/rom/xfileformats/formats/p12"
	"github.com/rom/xfileformats/formats/pdf"
	fpgp "github.com/rom/xfileformats/formats/pgp"
	"github.com/rom/xfileformats/formats/privkey"
	"github.com/rom/xfileformats/formats/puttykey"
	"github.com/rom/xfileformats/formats/sqlcipher"
	"github.com/rom/xfileformats/formats/sshkey"
	fvba "github.com/rom/xfileformats/formats/vbaproject"
	"github.com/rom/xfileformats/formats/zip"
)

// CandidateSource yields password candidates. It is an alias for the shared
// candidates.Source so sources from the xcrypto candidates package (and the
// pattern engine) are accepted directly. Implementations need not be
// thread-safe; the engine serializes access behind a feeder.
type CandidateSource = candidates.Source

// Accelerator is the optional batch-KDF offload (the opt-in xcrackd OpenCL
// tier, github.com/rom/xcrack/pkg/accel). It is re-exported here so callers set
// Options.Accelerator without importing the accel package directly. The default
// pure-Go build has no backend, so this stays nil and everything runs on the
// CPU; see Options.Accelerator.
type Accelerator = accel.Accelerator

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
	// KeyRecovered reports that the node was unlocked by a known-plaintext key
	// recovery (ZipCrypto) rather than a password; Password is then "".
	KeyRecovered bool
}

// Options configures an engine/Pool. Every CLI flag maps to a field here, so
// the library and CLI have identical capability (CON-3).
type Options struct {
	Workers         int // candidate-test goroutines within one file (0 => NumCPU)
	FileConcurrency int // container entries processed concurrently (0 => NumCPU; set 1 to disable)
	MaxProcs        int // global ceiling on concurrent candidate testers (0 => NumCPU)
	BatchSize       int // candidates per worker hand-off (0 => 1); amortizes channel overhead
	ThrottlePercent int // approximate CPU duty cycle 1..99 (0/100 => no throttle)

	// Behavior toggles are phrased so the zero value is the sensible default:
	// the engine recurses, promotes passwords, and stops on the first match
	// unless told otherwise.
	NoRecurse         bool // disable container decomposition (default: recurse)
	NoPromote         bool // disable password promotion (default: promote)
	CorpusPromotion   bool // promote recovered passwords across every file in a run (not just inner layers) and try the most repeatedly-successful ones first; requires promotion on (default: off)
	FindAll           bool // reserved: keep searching after the first match (phase 2)
	ExplodeDocuments  bool // decompose documents into parts (default false, opt-in)
	ContextCandidates bool // seed each search with candidates derived from the node name and plaintext harvested from plain sibling entries (default: off)
	HintCandidates    bool // seed each search with candidates derived from a format's embedded password hint (e.g. iWork .iwph, ZIP comment), tried right after promoted passwords (default: off)

	// HintRules, when set, expands each hint-derived base word into variants
	// (case/leet/append-digits/…) to also try. It is a word->variants function so
	// the engine stays decoupled from the rule compiler; the CLI builds it from a
	// hashcat-style rule file via --hint-rules. Applied only when HintCandidates
	// is on. nil => try the hint-derived base words only.
	HintRules func(base string) []string

	Limits Limits
	Budget Budget

	// Registry selects which formats are enabled. nil => DefaultRegistry().
	Registry *xfileformats.Registry

	OnProgress func(Progress)
	OnFound    func(Found)
	// OnAudit, if set, is called once per result node after a Process call with an
	// AuditEvent (for an audit log or trace). It carries no content and — unless
	// AuditIncludeSecrets is set — no password, so the default is safe to persist.
	OnAudit func(AuditEvent)
	// AuditIncludeSecrets, when true, lets the AuditEvent handed to OnAudit carry
	// the recovered password (AuditEvent.Password). It is opt-in: the zero value
	// keeps audit events secrets-free. It has no effect when OnAudit is nil.
	AuditIncludeSecrets bool
	Logger              Logger

	// CandidateProvider, when set, supplies candidates tried ahead of the
	// per-call source on every Process call (a pluggable live provider). nil
	// disables it.
	CandidateProvider CandidateProvider

	// KnownPlaintext, when enabled, lets the engine recover a ZipCrypto entry via a
	// known-plaintext key-recovery attack (no password) before falling back to the
	// password search. It is opt-in: the zero value disables it.
	KnownPlaintext KnownPlaintext

	// FastReject, when set, is a cheap per-format pre-check consulted before the
	// expensive KDF for every generated candidate (context- and brute-force-
	// derived): returning true discards the candidate without running Verify. It
	// lets an embedder encode a domain constraint (e.g. "the PIN is 6 digits") to
	// prune a hopeless keyspace. It is NOT applied to passwords promoted from an
	// outer layer (those are already proven), and it must be side-effect-free and
	// safe for concurrent use. A FastReject that is too aggressive only slows or
	// misses a crack; it can never cause a false positive.
	FastReject func(path string, candidate []byte) bool

	// Accelerator, when set, offloads the shared PBKDF2-HMAC-SHA1 key derivation
	// of acceleration-capable targets (whole-file xfileformats.Accelerable formats
	// such as DMG, and container entries carrying an Entry.Accel such as
	// WinZip-AES) to an external batch engine — the opt-in xcrackd OpenCL tier. It
	// is consulted only for the general keyspace sweep, and only for targets whose
	// derivation fits the backend's kernel; promoted/hint/context passwords are
	// always tried on the CPU first, and any backend error or unsupported
	// parameter falls back transparently to the unchanged CPU search. The
	// accelerator's output is always re-checked by the format's own authoritative
	// verifier, so it can never cause a false positive. nil (the default) keeps
	// every search on the CPU.
	Accelerator Accelerator

	// AccelBatch overrides how many candidates are derived per accelerator
	// dispatch. 0 (the default) uses the accelerator's autotuned size when it
	// implements accel.BatchTuner, otherwise a built-in default. Ignored without
	// an Accelerator.
	AccelBatch int

	// DualPipeline enables the dual CPU+GPU parallel pipeline: for an
	// acceleration-capable target, the CPU search and the accelerator sweep run
	// concurrently over ONE shared, de-duplicated candidate stream, and the first
	// to find a password cancels the other (both then advance to the next file).
	// Without it (the default) the accelerator sweeps the keyspace and the CPU
	// path runs only as a fallback — the CPU sits idle while the device works.
	// With it, the CPU's cheap guesses and the device's bulk sweep progress at the
	// same time, so a password near the front of the stream is found by the CPU
	// without waiting for a device batch. It is ignored when no Accelerator is set
	// or the target is not acceleration-capable. The device's hits are still
	// re-checked on the CPU (via the format's verifier), so it can never cause a
	// false positive.
	DualPipeline bool
}

// KnownPlaintext configures an opt-in known-plaintext key-recovery attack for
// ZipCrypto entries. When a plaintext fragment of an encrypted entry is known
// (e.g. a STORED file whose content the embedder already has, or a known magic),
// the internal key can be recovered directly — no password. The zero value is
// disabled (For == nil).
type KnownPlaintext struct {
	// For returns known plaintext for the entry at path, aligned to the start of
	// its encrypted data stream (for a STORED entry, the file's own leading
	// bytes), or nil when none is available. At least zipcrypto.MinKnownPlaintext
	// contiguous bytes are needed; more recovers faster.
	For func(path string) []byte
	// Offload, if non-nil, runs the search on an external engine (e.g.
	// zipcrypto.ExternalBkcrack) instead of the compute-heavy in-process attack.
	// The engine re-validates whatever it returns, so a faulty engine cannot
	// cause a false positive.
	Offload zipcrypto.Offloader
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
	// msoffice (legacy .doc/.xls/.ppt) shares the CFB/OLE2 magic with ooxml; it
	// is registered AFTER ooxml so an encrypted OOXML wrapper is probed first and
	// the engine falls back here only for the legacy binaries.
	msoffice.Register(r)
	pdf.Register(r)
	odf.Register(r)
	// iWork documents (.pages/.numbers/.key) are ZIP archives; iwork outranks the
	// generic zip format in Detect and declines non-iWork zips in Probe, so it
	// must be registered alongside zip (ranking is by Detect confidence).
	iwork.Register(r)
	archive.Register(r)
	age.Register(r)
	fpgp.Register(r)
	sshkey.Register(r)
	privkey.Register(r)
	jks.Register(r)
	keepass.Register(r)
	fp12.Register(r)
	puttykey.Register(r)
	fdmg.Register(r)
	access.Register(r)
	// Ethereum keystore (Web3 Secret Storage v3) wallet JSON; detects on its
	// unique "crypto"/"ciphertext"/"kdf" markers, so it never claims a non-wallet
	// file.
	ethwallet.Register(r)
	return r
}

// ForceRegistry returns a registry containing only the named format, for the
// CLI's `--as` force-format option. It exists for formats that carry no magic
// bytes and so cannot be auto-detected (SQLCipher): such a format greedily
// claims the input, so it is never in DefaultRegistry and is reachable only
// when the caller targets it. ok is false for an unknown name.
func ForceRegistry(name string) (*xfileformats.Registry, bool) {
	r := xfileformats.NewRegistry()
	switch strings.ToLower(name) {
	case "sqlcipher":
		sqlcipher.Register(r)
		return r, true
	case "vbaproject", "vba":
		fvba.Register(r)
		return r, true
	default:
		return nil, false
	}
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
	metrics metrics
	learned *learnedSet // corpus-wide recovered passwords (used when CorpusPromotion)
}

// NewPool returns a Pool configured by opts (defaults applied). The cracking
// engine's global semaphore keeps the total number of live candidate testers at
// or below MaxProcs across every concurrent Process call.
func NewPool(opts Options) *Pool {
	opts.normalize()
	cr := attack.New(attack.Options{
		Workers:         opts.Workers,
		MaxProcs:        opts.MaxProcs,
		MaxCandidates:   opts.Limits.MaxCandidates,
		BatchSize:       opts.BatchSize,
		ThrottlePercent: opts.ThrottlePercent,
	})
	return &Pool{opts: opts, cracker: cr, learned: newLearnedSet(0)}
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
	spill := newSpillSet(p.opts.Limits.SpillThreshold, p.opts.Limits.TempDir)
	e := &engine{opts: p.opts, cracker: p.cracker, spill: spill}
	// Stream the input into a source (to disk when large), capping at
	// MaxEntrySize: the section reader is pre-bounded, so an oversize root file
	// is truncated to the cap rather than rejected (as the whole-file read was).
	if size < 0 {
		size = 0
	}
	limit := size
	if m := p.opts.Limits.MaxEntrySize; m > 0 && limit > m {
		limit = m
	}
	rootSrc, err := spill.materializeReader(io.NewSectionReader(src, 0, limit), 0)
	if err != nil {
		p.metrics.processingErrors.Add(1)
		return nil, err
	}
	// A pluggable live provider's candidates are tried ahead of the per-call set.
	effective := candidates
	if p.opts.CandidateProvider != nil {
		effective = chainSources(p.opts.CandidateProvider.Candidates(ctx), candidates)
	}
	acc := newAccounting(p.opts.Limits)
	// Corpus-wide promotion threads the Pool's learned-password set through this
	// run's promoter, so finds cross file boundaries; otherwise promotion stays
	// per-file (inner layers only).
	var shared *learnedSet
	if p.opts.CorpusPromotion && !p.opts.NoPromote {
		shared = p.learned
	}
	prom := newPromoter(!p.opts.NoPromote, shared)
	root := e.decompose(ctx, "", rootSrc, 0, nil, prom, acc, effective, nil)
	stats := acc.snapshot()
	stats.Elapsed = time.Since(start)
	res := &Result{Root: root, Stats: stats, spills: spill}
	p.metrics.record(res, stats.Elapsed)
	if p.opts.OnAudit != nil && root != nil {
		root.Walk(func(n *Node) {
			p.opts.OnAudit(n.AuditEvent(p.opts.AuditIncludeSecrets))
		})
	}
	return res, nil
}

// Process is the one-shot convenience entry point: it builds a single-use Pool,
// processes src, and returns the result.
func Process(ctx context.Context, src io.ReaderAt, size int64, candidates CandidateSource, opts Options) (*Result, error) {
	p := NewPool(opts)
	defer p.Close()
	return p.Process(ctx, src, size, candidates)
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
