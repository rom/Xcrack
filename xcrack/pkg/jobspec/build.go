package jobspec

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/pattern"
)

// Generator bounds, mirroring the CLI defaults so a spec and the equivalent CLI
// invocation build the same keyspaces.
const (
	princeMaxLen   = 32        // drop PRINCE concatenations longer than this
	princeMaxWords = 3         // at most this many words per PRINCE chain
	princeMax      = 5_000_000 // cap on PRINCE candidates per file
	keyWalkMin     = 4         // shortest keyboard walk
	keyWalkMax     = 10        // longest keyboard walk
	keyWalkCount   = 1_000_000 // cap on generated walks
	markovMinLen   = 1         // shortest Markov guess
	markovMaxLen   = 16        // longest Markov guess

	defaultPCFGMax         = 100_000   // PCFG guesses when Search.PCFGMax is 0
	defaultMarkovMax       = 1_000_000 // Markov guesses when Search.MarkovMax is 0
	defaultMarkovThreshold = 15        // per-position branching when Search.MarkovThreshold is 0
	defaultOrderMax        = 1_000_000 // reorder buffer when Search.OrderMax is 0
	trainingWordCap        = 1 << 20   // bound on words used to train PCFG/Markov models
)

// Runtime carries per-run inputs resolved outside the static Spec: priority
// passwords (the found-password cache/potfile, password files handled here, an
// environment-provided password, imported recovered-password envelopes) tried
// ahead of everything, and the cached passwords re-mangled by the loopback pass.
//
// The static Spec describes what to try; Runtime carries the small amount of
// live, caller-resolved state the spec cannot name.
type Runtime struct {
	// PriorityPasswords are tried first on every file, ahead of the generators.
	PriorityPasswords []string
	// LoopbackPasswords are fed back through the mangling rules when
	// Spec.Search.Loopback is set (typically the potfile's cached passwords).
	LoopbackPasswords []string
}

// BuildOptions maps the spec's engine knobs onto xcrack.Options: concurrency,
// resource limits, recursion/promotion toggles, time budgets, the compiled
// hint-rule mangler and the force-format registry. It deliberately sets nothing
// surface-specific — the Logger, Accelerator and the OnFound/OnProgress/OnAudit
// callbacks are wired by the caller (CLI, library embedder, or web backend),
// since those differ per surface. Unset numeric knobs keep the engine defaults.
func (s *Spec) BuildOptions() (xcrack.Options, error) {
	opts := xcrack.DefaultOptions()
	opts.Limits = xcrack.DefaultLimits()

	if v := s.Concurrency.Workers; v != 0 {
		opts.Workers = v
	}
	if v := s.Concurrency.MaxProcs; v != 0 {
		opts.MaxProcs = v
	}
	if v := s.Concurrency.FileJobs; v != 0 {
		opts.FileConcurrency = v
	}
	opts.BatchSize = s.Concurrency.BatchSize       // 0 => auto
	opts.ThrottlePercent = s.Concurrency.Throttle  // 0 => off
	opts.DualPipeline = s.Concurrency.DualPipeline // honoured only when an Accelerator is wired

	opts.NoRecurse = !s.recurse()
	opts.ExplodeDocuments = s.Recursion.ExplodeDocuments
	opts.NoPromote = !s.promote()
	opts.CorpusPromotion = s.Search.Adaptive
	opts.ContextCandidates = s.Search.Context
	opts.HintCandidates = s.Search.Hint || len(s.Search.HintRules) > 0
	if opts.HintCandidates {
		mangler, err := buildHintRules(s.Search.HintRules)
		if err != nil {
			return opts, fmt.Errorf("search.hint_rules: %w", err)
		}
		opts.HintRules = mangler
	}

	if v := s.Limits.MaxDepth; v != 0 {
		opts.Limits.MaxDepth = v
	}
	if v := s.Limits.MaxTotalBytes; v != 0 {
		opts.Limits.MaxTotalBytes = v
	}
	if v := s.Limits.MaxNodes; v != 0 {
		opts.Limits.MaxNodes = v
	}
	if v := s.Limits.MaxEntrySize; v != 0 {
		opts.Limits.MaxEntrySize = v
	}
	if v := s.Limits.MaxRatio; v != 0 {
		opts.Limits.MaxRatio = v
	}
	opts.Limits.MaxCandidates = s.Limits.MaxCandidates // 0 => unlimited

	if s.Budget.PerFile != "" {
		d, err := parseDuration(s.Budget.PerFile)
		if err != nil {
			return opts, fmt.Errorf("budget.per_file: %w", err)
		}
		opts.Budget.PerFile = d
	}
	if s.Budget.Total != "" {
		d, err := parseDuration(s.Budget.Total)
		if err != nil {
			return opts, fmt.Errorf("budget.total: %w", err)
		}
		opts.Budget.Total = d
	}

	if s.Input.As != "" {
		reg, ok := forceRegistry(s.Input.As)
		if !ok {
			return opts, fmt.Errorf("input.as: unknown force-format %q (supported: sqlcipher, vba)", s.Input.As)
		}
		opts.Registry = reg
	}
	return opts, nil
}

// Assembler holds the one-time-built state derived from a Spec — compiled
// patterns, trained PCFG/Markov models, the resolved candidate lists — and
// produces a fresh CandidateSource per file. Candidate sources are stateful and
// used concurrently across files, so Candidates must be called once per file.
//
// An Assembler is safe for concurrent Candidates calls: it holds only immutable
// derived state and builds each file's source from fresh readers.
type Assembler struct {
	spec *Spec
	rt   Runtime

	patternSet *pattern.Set
	customCS   map[rune]string
	maskSpecs  []string
	hcMasks    []*pattern.Mask
	hybridApp  []*pattern.Mask
	hybridPre  []*pattern.Mask

	pcfg       *candidates.PCFG
	markov     *candidates.Markov
	markovPos  *candidates.MarkovPos
	orderModel *candidates.Markov
	enc        candidates.Encoding

	incMin, incMax         int
	shardIndex, shardCount int

	useDefault  bool
	useSwedish  bool
	useSpray    bool
	sprayTokens []string
	sprayYears  []int

	allPasswords []string
	allWordlists []string
	allBreach    []string
	breachMin    int64
}

// NewAssembler validates the spec, compiles its patterns, trains any requested
// PCFG/Markov models and resolves its candidate lists once. It reads the pattern
// and password files the spec references, so it can touch the filesystem and may
// fail; a returned error names the offending block.
func NewAssembler(s *Spec, rt Runtime) (*Assembler, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	a := &Assembler{
		spec:       s,
		rt:         rt,
		useDefault: s.useDefaultList(),
		useSwedish: s.Candidates.Swedish,
	}

	// Pattern set: inline masks/rules/charsets from the Patterns block, plus any
	// reproducible generated rules.
	var genRules []string
	if s.Patterns.GenerateRules > 0 {
		genRules = pattern.GenerateRules(s.Patterns.GenerateRules, s.Patterns.GenerateRulesSeed)
	}
	set, cs, masks, err := buildPatternSet(s, genRules)
	if err != nil {
		return nil, fmt.Errorf("patterns: %w", err)
	}
	a.patternSet, a.customCS, a.maskSpecs = set, cs, masks

	if a.hybridApp, err = compileMasks(s.Search.HybridAppend, cs); err != nil {
		return nil, fmt.Errorf("search.hybrid_append: %w", err)
	}
	if a.hybridPre, err = compileMasks(s.Search.HybridPrepend, cs); err != nil {
		return nil, fmt.Errorf("search.hybrid_prepend: %w", err)
	}
	for _, hm := range s.Patterns.HCMask {
		ms, herr := pattern.LoadHCMask(hm, cs)
		if herr != nil {
			return nil, fmt.Errorf("patterns.hcmask: %w", herr)
		}
		a.hcMasks = append(a.hcMasks, ms...)
	}

	// These were validated in Spec.Validate, so the errors cannot fire here; the
	// returned values are what we need.
	a.incMin, a.incMax, _ = parseIncrement(s.Search.Increment)
	a.shardIndex, a.shardCount, _ = parseShard(s.Search.Shard)
	if a.enc, err = candidates.ParseEncoding(s.Candidates.Encoding); err != nil {
		return nil, fmt.Errorf("candidates.encoding: %w", err)
	}

	a.sprayTokens = append([]string{}, s.Search.SprayTokens...)
	a.sprayYears = append([]int{}, s.Search.SprayYears...)
	a.useSpray = s.Search.Spray || len(a.sprayTokens) > 0 || len(a.sprayYears) > 0

	// Priority passwords first (caller-supplied), then password-file words, then
	// the spec's explicit passwords — all tried ahead of the generators.
	pw := append([]string{}, rt.PriorityPasswords...)
	if len(s.Candidates.PasswordFiles) > 0 {
		words, perr := passwordsFromFiles(s.Candidates.PasswordFiles)
		if perr != nil {
			return nil, fmt.Errorf("candidates.password_files: %w", perr)
		}
		pw = append(pw, words...)
	}
	pw = append(pw, s.Candidates.Passwords...)
	a.allPasswords = pw
	a.allWordlists = append([]string{}, s.Candidates.Wordlists...)
	a.allBreach = append([]string{}, s.Candidates.Breach...)
	a.breachMin = s.Candidates.BreachMinCount

	// Statistical models, trained once from a bounded candidate corpus.
	if s.Search.PCFG {
		a.pcfg = candidates.TrainPCFG(collectTrainingWords(a.allPasswords, a.useDefault, a.allWordlists, trainingWordCap))
	}
	if s.Search.Markov || s.Search.MarkovPos {
		samples := trainingSamples(a.allPasswords, a.useDefault, a.allWordlists)
		if s.Search.MarkovPos {
			a.markovPos = candidates.TrainMarkovPos(samples)
		} else {
			a.markov = candidates.TrainMarkov(samples)
		}
	}
	if strings.EqualFold(s.Search.Order, "markov") {
		a.orderModel = candidates.TrainMarkov(trainingSamples(a.allPasswords, a.useDefault, a.allWordlists))
	}
	return a, nil
}

// Candidates assembles a fresh candidate source for one file. It mirrors the
// CLI's per-file pipeline exactly: priority passwords and loopback first, then
// the statistical generators, the name-context seeds, the default/Swedish/spray
// sets, the breach corpora, the mangled wordlists, the mask keyspaces, the
// combinator and hybrid/PRINCE/toggle/keyboard-walk generators — all then length-
// filtered, transcoded and sharded.
func (a *Assembler) Candidates(path string) xcrack.CandidateSource {
	s := a.spec
	var srcs []candidates.Source

	if len(a.allPasswords) > 0 {
		srcs = append(srcs, candidates.Explicit(a.allPasswords...))
	}
	if s.Search.Loopback && len(a.rt.LoopbackPasswords) > 0 {
		srcs = append(srcs, a.patternSet.ApplyRules(candidates.Explicit(a.rt.LoopbackPasswords...)))
	}
	if a.pcfg != nil {
		max := s.Search.PCFGMax
		if max <= 0 {
			max = defaultPCFGMax
		}
		srcs = append(srcs, a.pcfg.Source(max))
	}
	if a.markov != nil || a.markovPos != nil {
		topK := s.Search.MarkovThreshold
		if topK <= 0 {
			topK = defaultMarkovThreshold
		}
		max := s.Search.MarkovMax
		if max <= 0 {
			max = defaultMarkovMax
		}
		if a.markovPos != nil {
			srcs = append(srcs, candidates.MarkovGenPos(a.markovPos, markovMinLen, markovMaxLen, max, topK))
		} else {
			srcs = append(srcs, candidates.MarkovGenTopK(a.markov, markovMinLen, markovMaxLen, max, topK))
		}
	}
	// Top-level file name context: nested nodes derive their own names in the
	// engine, but the root file's name is only known here.
	if s.Search.Context {
		if names := candidates.FromName(filepath.Base(path)); len(names) > 0 {
			srcs = append(srcs, candidates.Explicit(names...))
		}
	}
	if a.useDefault {
		srcs = append(srcs, candidates.DefaultList())
	}
	if a.useSwedish {
		srcs = append(srcs, candidates.Swedish())
	}
	if a.useSpray {
		srcs = append(srcs, candidates.Spray(a.sprayTokens, a.sprayYears, 0))
	}
	for _, bl := range a.allBreach {
		srcs = append(srcs, a.patternSet.ApplyRules(candidates.BreachFile(bl, a.breachMin)))
	}
	for _, wl := range a.allWordlists {
		var base candidates.Source
		if wl == "-" {
			base = candidates.Stdin()
		} else {
			base = a.reorder(candidates.File(wl))
		}
		srcs = append(srcs, a.patternSet.ApplyRules(base))
	}
	// Masks: with --increment each mask spec expands into shortest-first prefix
	// masks over the requested token range instead of its full length.
	if a.incMin > 0 || a.incMax > 0 {
		for _, spec := range a.maskSpecs {
			for _, inc := range pattern.ExpandIncrement(spec, a.incMin, a.incMax) {
				if m, err := pattern.CompileMask(inc, a.customCS); err == nil {
					srcs = append(srcs, m.Source())
				}
			}
		}
	} else {
		srcs = append(srcs, a.patternSet.MaskSources()...)
	}
	for _, m := range a.hcMasks {
		srcs = append(srcs, m.Source())
	}
	if s.Search.Combinator.Left != "" && s.Search.Combinator.Right != "" {
		srcs = append(srcs, candidates.Combinator(
			candidates.File(s.Search.Combinator.Left),
			candidates.File(s.Search.Combinator.Right),
			[]byte(s.Search.Combinator.Sep)))
	}
	if len(a.hybridApp) > 0 || len(a.hybridPre) > 0 {
		for _, m := range a.hybridApp {
			if w := a.freshWordlist(); w != nil {
				srcs = append(srcs, pattern.Hybrid(w, m, true))
			}
		}
		for _, m := range a.hybridPre {
			if w := a.freshWordlist(); w != nil {
				srcs = append(srcs, pattern.Hybrid(w, m, false))
			}
		}
	}
	if s.Search.ToggleCase {
		if w := a.freshWordlist(); w != nil {
			srcs = append(srcs, candidates.ToggleCase(w, 0))
		}
	}
	if s.Search.Prince {
		if w := a.freshWordlist(); w != nil {
			srcs = append(srcs, candidates.Prince(w, 1, princeMaxLen, princeMaxWords, princeMax))
		}
	}
	if s.Search.KeyboardWalk {
		srcs = append(srcs, candidates.KeyboardWalk(keyWalkMin, keyWalkMax, keyWalkCount))
	}

	chain := candidates.Chain(srcs...)
	chain = candidates.LengthFilter(chain, s.Candidates.MinLength, s.Candidates.MaxLength)
	chain = candidates.Encode(chain, a.enc)
	return candidates.Shard(chain, a.shardIndex, a.shardCount)
}

// Keyspace returns the candidate count for one file when it is finite and known
// (an explicit list or a mask), or -1 for an open-ended stream (wordlists /
// generators). It is cheap — Len does not iterate.
func (a *Assembler) Keyspace(path string) int64 {
	if s := a.Candidates(path); s != nil {
		return s.Len()
	}
	return -1
}

// freshWordlist returns a re-iterable chain of the file wordlists (stdin
// excluded, since it cannot be re-read), shared by the hybrid/PRINCE/toggle
// builders. nil when there are no file wordlists.
func (a *Assembler) freshWordlist() candidates.Source {
	var ws []candidates.Source
	for _, wl := range a.allWordlists {
		if wl == "-" {
			continue
		}
		ws = append(ws, candidates.File(wl))
	}
	if len(ws) == 0 {
		return nil
	}
	return candidates.Chain(ws...)
}

// reorder wraps a finite wordlist source so its head is the likeliest words
// (identity unless Search.Order == "markov").
func (a *Assembler) reorder(src candidates.Source) candidates.Source {
	if a.orderModel == nil || src == nil {
		return src
	}
	max := a.spec.Search.OrderMax
	if max <= 0 {
		max = defaultOrderMax
	}
	return candidates.ByScore(src, a.orderModel.Scorer(), max)
}
