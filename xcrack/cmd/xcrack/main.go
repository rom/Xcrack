// Command xcrack is the CLI front-end to the Xcrack engine. It is a thin
// wrapper: every capability it exposes is a field on xcrack.Options, so the
// embeddable library has full parity with the CLI.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/pattern"
)

const version = "0.1.0-mvp"

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-v":
			fmt.Printf("xcrack %s (go %s)\n", version, runtime.Version())
			return 0
		case "identify":
			return runIdentify(args[1:])
		case "kp":
			return runKP(args[1:])
		case "hashline":
			return runHashline(args[1:])
		case "help", "-h", "--help":
			usage()
			return 0
		}
	}
	return runCrack(args)
}

type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func runCrack(args []string) int {
	fs_ := flag.NewFlagSet("xcrack", flag.ContinueOnError)
	var sources, wordlists, passwords, patterns stringSlice
	reg := func(p *stringSlice, long, short, help string) {
		fs_.Var(p, long, help)
		if short != "" {
			fs_.Var(p, short, "alias for --"+long)
		}
	}
	reg(&sources, "source", "s", "source file/dir/glob (repeatable)")
	reg(&wordlists, "wordlist", "w", "wordlist file; - for stdin; gzip auto-detected (repeatable)")
	reg(&passwords, "password", "p", "explicit candidate password (repeatable)")
	reg(&patterns, "pattern", "", "mask/rule pattern file (repeatable)")

	out := fs_.String("out", "", "write decrypted tree to this directory")
	fs_.StringVar(out, "o", "", "alias for --out")
	configPath := fs_.String("config", "", "YAML config file")
	fs_.StringVar(configPath, "c", "", "alias for --config")

	format := fs_.String("format", "text", "output format: text|json|jsonl")
	logLevel := fs_.String("log-level", "info", "log level: debug|info|warn|error")
	resultsFile := fs_.String("results-file", "", "write JSON manifest/results here")

	workers := fs_.Int("workers", 0, "candidate-test goroutines per file (0=NumCPU)")
	fileJobs := fs_.Int("file-jobs", 0, "files processed concurrently (0=NumCPU)")
	maxProcs := fs_.Int("max-procs", 0, "global ceiling on concurrent candidate testers (0=NumCPU)")
	timeout := fs_.Duration("timeout", 0, "per-file time budget (e.g. 30s)")
	maxDuration := fs_.Duration("max-duration", 0, "whole-run deadline")
	batchSize := fs_.Int("batch-size", 0, "candidates per worker hand-off (0=auto)")
	throttle := fs_.Int("throttle", 0, "approximate CPU duty cycle percent 1..99 (0=off)")

	recurse := fs_.Bool("recurse", true, "decompose containers")
	noRecurse := fs_.Bool("no-recurse", false, "disable container decomposition")
	explode := fs_.Bool("explode-documents", false, "decompose documents into internal parts")
	noDefault := fs_.Bool("no-default-list", false, "disable the built-in common-password list")
	findAll := fs_.Bool("find-all", false, "search every encrypted node even if some stay locked (default: on)")
	contextF := fs_.Bool("context", false, "seed guesses from the file/entry name and plaintext harvested from plain sibling entries")
	hintF := fs_.Bool("hint", false, "derive guesses from a file's embedded password hint (iWork .iwph, ZIP comment), tried first")
	hintRulesF := fs_.String("hint-rules", "", "hashcat-style rule file applied to hint-derived words (implies --hint)")
	pcfgF := fs_.Bool("pcfg", false, "train a PCFG on the candidate words and generate guesses in probability order")
	pcfgMax := fs_.Int("pcfg-max", 100000, "max PCFG guesses to generate (with --pcfg)")
	markovF := fs_.Bool("markov", false, "train a Markov model on the candidate words and generate guesses best-first")
	markovMax := fs_.Int("markov-max", 1_000_000, "max Markov guesses to generate (with --markov)")
	incrementF := fs_.String("increment", "", "expand each mask over a token-length range MIN:MAX, shortest first (hashcat --increment)")
	combLeft := fs_.String("combinator-left", "", "left wordlist for a combinator attack (each left word + each right word)")
	combRight := fs_.String("combinator-right", "", "right wordlist for a combinator attack (requires --combinator-left)")
	combSep := fs_.String("combinator-sep", "", "separator inserted between the two words in a combinator attack")
	asF := fs_.String("as", "", "force the input to be treated as SCHEME, bypassing content detection (for formats with no magic bytes, e.g. 'sqlcipher')")
	var hybridAppend, hybridPrepend stringSlice
	fs_.Var(&hybridAppend, "hybrid-append", "append every expansion of MASK to each wordlist word (hashcat dict+mask; repeatable)")
	fs_.Var(&hybridPrepend, "hybrid-prepend", "prepend every expansion of MASK to each wordlist word (hashcat mask+dict; repeatable)")
	toggleF := fs_.Bool("toggle-case", false, "also try case-toggle variants of each wordlist word (hashcat toggle attack)")
	princeF := fs_.Bool("prince", false, "also try PRINCE chains (length-ordered concatenations of wordlist words)")
	keywalkF := fs_.Bool("keyboard-walk", false, "also try keyboard-adjacency walks (QWERTY)")
	shardF := fs_.String("shard", "", "distributed cracking: test only shard I of N of the keyspace, e.g. --shard 0/4 (run 0/4..3/4 on separate machines; promoted/context/hint guesses are tried by every shard)")
	adaptiveF := fs_.Bool("adaptive", false, "corpus-wide adaptive promotion: try passwords recovered from any file first on the rest (most-successful first), smallest files first")
	sprayF := fs_.Bool("spray", false, "also try a curated password-spraying set (common + season/year patterns), tried early")
	var sprayTokens stringSlice
	fs_.Var(&sprayTokens, "spray-token", "org/product/user token mangled into the spray set (repeatable; implies --spray)")
	var sprayYears stringSlice
	fs_.Var(&sprayYears, "spray-year", "year to use in spray patterns (repeatable; default: current and previous)")
	var breachLists stringSlice
	fs_.Var(&breachLists, "breach", "frequency-annotated breach corpus FILE (count-prefixed or password:count; gzip ok; repeatable)")
	breachMinF := fs_.Int64("breach-min-count", 0, "drop breach entries seen fewer than N times (0=keep all)")

	progressF := fs_.Bool("progress", false, "print live progress (files/candidates/rate/ETA) to stderr")
	var passwordFiles stringSlice
	fs_.Var(&passwordFiles, "password-file", "read candidate passwords (one per line) from FILE (repeatable)")
	passwordEnv := fs_.String("password-env", "", "read a candidate password from this environment variable")
	potfilePath := fs_.String("potfile", "", "load recovered passwords from, and append new ones to, this file")
	checkpointPath := fs_.String("checkpoint", "", "persist/resume search position for a single long run (single-target only)")

	maxDepth := fs_.Int("max-depth", 0, "max nesting depth (0=default 32)")
	maxTotal := fs_.Int64("max-total-bytes", 0, "cumulative decompressed byte budget")
	maxNodes := fs_.Int("max-nodes", 0, "max extracted entries")
	maxEntry := fs_.Int64("max-entry-size", 0, "max single-entry size")
	maxCand := fs_.Int64("max-candidates", 0, "max candidates tested per encrypted node (0=unlimited)")

	fs_.Usage = usage
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	set := map[string]bool{}
	fs_.Visit(func(f *flag.Flag) { set[f.Name] = true })

	var cfg *fileConfig
	if *configPath != "" {
		c, err := loadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack: config: %v\n", err)
			return 2
		}
		cfg = c
	}

	// resolve settings with precedence: flags > env > config > defaults
	opts := xcrack.DefaultOptions()
	opts.Workers = resolveInt(set["workers"], *workers, env("XCRACK_WORKERS"), cfgInt(cfg, func(c *fileConfig) int { return c.Concurrency.Workers }), opts.Workers)
	opts.FileConcurrency = resolveInt(set["file-jobs"], *fileJobs, env("XCRACK_FILE_JOBS"), cfgInt(cfg, func(c *fileConfig) int { return c.Concurrency.FileJobs }), runtime.NumCPU())
	opts.MaxProcs = resolveInt(set["max-procs"], *maxProcs, env("XCRACK_MAX_PROCS"), cfgInt(cfg, func(c *fileConfig) int { return c.Concurrency.MaxProcs }), opts.MaxProcs)

	opts.ExplodeDocuments = *explode || (cfg != nil && cfg.Recursion.ExplodeDocuments)
	opts.NoRecurse = (set["no-recurse"] && *noRecurse) || (set["recurse"] && !*recurse)
	if cfg != nil && cfg.Recursion.Recurse != nil && !set["recurse"] && !set["no-recurse"] {
		opts.NoRecurse = !*cfg.Recursion.Recurse
	}
	if cfg != nil && cfg.Search.Promote != nil {
		opts.NoPromote = !*cfg.Search.Promote
	}
	opts.FindAll = *findAll
	opts.CorpusPromotion = *adaptiveF || (cfg != nil && cfg.Search.Adaptive)
	opts.ContextCandidates = *contextF || (cfg != nil && cfg.Search.Context)
	opts.HintCandidates = *hintF || *hintRulesF != "" || (cfg != nil && (cfg.Search.Hint || len(cfg.Search.HintRules) > 0))
	if opts.HintCandidates {
		mangler, herr := buildHintRules(*hintRulesF, cfg)
		if herr != nil {
			fmt.Fprintf(os.Stderr, "xcrack: hint-rules: %v\n", herr)
			return 2
		}
		opts.HintRules = mangler
	}

	opts.Limits = xcrack.DefaultLimits()
	opts.Limits.MaxDepth = resolveInt(set["max-depth"], *maxDepth, "", cfgInt(cfg, func(c *fileConfig) int { return c.Limits.MaxDepth }), opts.Limits.MaxDepth)
	opts.Limits.MaxTotalBytes = resolveInt64(set["max-total-bytes"], *maxTotal, cfgInt64(cfg, func(c *fileConfig) int64 { return c.Limits.MaxTotalBytes }), opts.Limits.MaxTotalBytes)
	opts.Limits.MaxNodes = resolveInt(set["max-nodes"], *maxNodes, "", cfgInt(cfg, func(c *fileConfig) int { return c.Limits.MaxNodes }), opts.Limits.MaxNodes)
	opts.Limits.MaxEntrySize = resolveInt64(set["max-entry-size"], *maxEntry, cfgInt64(cfg, func(c *fileConfig) int64 { return c.Limits.MaxEntrySize }), opts.Limits.MaxEntrySize)
	opts.Limits.MaxCandidates = resolveInt64(set["max-candidates"], *maxCand, cfgInt64(cfg, func(c *fileConfig) int64 { return c.Limits.MaxCandidates }), 0)

	opts.BatchSize = resolveInt(set["batch-size"], *batchSize, "", cfgInt(cfg, func(c *fileConfig) int { return c.Concurrency.BatchSize }), 0)
	opts.ThrottlePercent = resolveInt(set["throttle"], *throttle, env("XCRACK_THROTTLE"), cfgInt(cfg, func(c *fileConfig) int { return c.Concurrency.Throttle }), 0)
	opts.Budget.PerFile = *timeout
	opts.Budget.Total = *maxDuration
	if cfg != nil {
		if d, err := parseDuration(cfg.Budget.PerFile); err == nil && !set["timeout"] && d > 0 {
			opts.Budget.PerFile = d
		}
		if d, err := parseDuration(cfg.Budget.Total); err == nil && !set["max-duration"] && d > 0 {
			opts.Budget.Total = d
		}
	}

	outFormat := firstNonEmpty(flagIf(set["format"], *format), env("XCRACK_FORMAT_STR"), cfgStr(cfg, func(c *fileConfig) string { return c.Output.Format }), "text")
	resFile := firstNonEmpty(flagIf(set["results-file"], *resultsFile), cfgStr(cfg, func(c *fileConfig) string { return c.Output.ResultsFile }), "")
	logLvl := firstNonEmpty(flagIf(set["log-level"], *logLevel), cfgStr(cfg, func(c *fileConfig) string { return c.Output.LogLevel }), "info")
	opts.Logger = newLogger(logLvl)

	// Build the pattern set from --pattern files and the config's patterns block.
	patternSet, customCharsets, maskSpecs, err := buildPatternSet(patterns, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: pattern: %v\n", err)
		return 2
	}
	// Hybrid attack masks (wordlist ± mask), from flags and the config.
	allHybridAppend := append([]string{}, hybridAppend...)
	allHybridPrepend := append([]string{}, hybridPrepend...)
	if cfg != nil {
		allHybridAppend = append(allHybridAppend, cfg.Search.HybridAppend...)
		allHybridPrepend = append(allHybridPrepend, cfg.Search.HybridPrepend...)
	}
	hybridAppendMasks, err := compileMasks(allHybridAppend, customCharsets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: hybrid-append: %v\n", err)
		return 2
	}
	hybridPrependMasks, err := compileMasks(allHybridPrepend, customCharsets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: hybrid-prepend: %v\n", err)
		return 2
	}

	// assemble sources
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) == 0 {
		fmt.Fprintln(os.Stderr, "xcrack: no sources given (use --source or positional paths)")
		usage()
		return 2
	}
	files, err := expandSources(srcArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "xcrack: no matching source files")
		return 2
	}
	if *checkpointPath != "" && len(files) != 1 {
		fmt.Fprintln(os.Stderr, "xcrack: --checkpoint requires exactly one source (single-target resume)")
		return 2
	}

	// candidate builder (fresh per file; sources are stateful and used concurrently)
	useDefault := !*noDefault
	if cfg != nil && cfg.Candidates.UseDefaultList != nil {
		useDefault = *cfg.Candidates.UseDefaultList
	}
	cfgPasswords, cfgWordlists, cfgBreach := []string(nil), []string(nil), []string(nil)
	if cfg != nil {
		cfgPasswords = cfg.Candidates.Passwords
		cfgWordlists = cfg.Candidates.Wordlists
		cfgBreach = cfg.Candidates.Breach
	}
	// Priority passwords (tried first everywhere): the potfile, password files,
	// and an environment-provided password keep secrets off the command line.
	var priorityPW []string
	var pot *potfile
	if *potfilePath != "" {
		pot = loadPotfile(*potfilePath)
		priorityPW = append(priorityPW, pot.passwords()...)
	}
	if len(passwordFiles) > 0 {
		pf, err := passwordsFromFiles(passwordFiles)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack: password-file: %v\n", err)
			return 2
		}
		priorityPW = append(priorityPW, pf...)
	}
	if v, ok := passwordFromEnv(*passwordEnv); ok {
		priorityPW = append(priorityPW, v)
	}
	allPasswords := append(append(append([]string{}, priorityPW...), passwords...), cfgPasswords...)
	allWordlists := append(append([]string{}, wordlists...), cfgWordlists...)
	allBreach := append(append([]string{}, breachLists...), cfgBreach...)
	breachMin := *breachMinF
	if breachMin == 0 && cfg != nil && cfg.Candidates.BreachMinCount > 0 {
		breachMin = cfg.Candidates.BreachMinCount
	}
	sprayTok := append([]string{}, sprayTokens...)
	if cfg != nil {
		sprayTok = append(sprayTok, cfg.Search.SprayTokens...)
	}
	var sprayYearInts []int
	for _, y := range sprayYears {
		if n, err := strconv.Atoi(strings.TrimSpace(y)); err == nil {
			sprayYearInts = append(sprayYearInts, n)
		}
	}
	useSpray := *sprayF || len(sprayTok) > 0 || len(sprayYearInts) > 0 || (cfg != nil && cfg.Search.Spray)
	shardSpec := *shardF
	if shardSpec == "" && cfg != nil {
		shardSpec = cfg.Search.Shard
	}
	shardIndex, shardCount, serr := parseShard(shardSpec)
	if serr != nil {
		fmt.Fprintf(os.Stderr, "xcrack: --shard: %v\n", serr)
		return 2
	}

	// Optional PCFG / Markov: trained once from the candidate corpus (explicit
	// passwords, the built-in list, and wordlist files, bounded), then cloned per
	// file.
	var pcfgModel *candidates.PCFG
	if *pcfgF {
		pcfgModel = candidates.TrainPCFG(collectTrainingWords(allPasswords, useDefault, allWordlists, 1<<20))
	}
	var markovModel *candidates.Markov
	if *markovF || (cfg != nil && cfg.Search.Markov) {
		words := collectTrainingWords(allPasswords, useDefault, allWordlists, 1<<20)
		samples := make([][]byte, len(words))
		for i, w := range words {
			samples[i] = []byte(w)
		}
		markovModel = candidates.TrainMarkov(samples)
	}

	// Mask length incrementing (hashcat --increment): expand each configured mask
	// into shortest-first prefix masks over MIN:MAX tokens, in place of the
	// full-length masks.
	incMin, incMax, ierr := parseIncrement(*incrementF)
	if ierr != nil {
		fmt.Fprintf(os.Stderr, "xcrack: --increment: %v\n", ierr)
		return 2
	}
	if (*combLeft == "") != (*combRight == "") {
		fmt.Fprintln(os.Stderr, "xcrack: --combinator-left and --combinator-right must be given together")
		return 2
	}
	// --as forces a specific scheme, bypassing content detection (for magic-less
	// formats such as SQLCipher that cannot be auto-detected).
	if *asF != "" {
		reg, ok := xcrack.ForceRegistry(*asF)
		if !ok {
			fmt.Fprintf(os.Stderr, "xcrack: --as: unknown force-format %q (supported: sqlcipher)\n", *asF)
			return 2
		}
		opts.Registry = reg
	}

	// Extra generators (flags, or the config's search block).
	genToggle := *toggleF || (cfg != nil && cfg.Search.ToggleCase)
	genPrince := *princeF || (cfg != nil && cfg.Search.Prince)
	genKeyWalk := *keywalkF || (cfg != nil && cfg.Search.KeyboardWalk)
	const (
		princeMaxLen   = 32        // drop concatenations longer than this
		princeMaxWords = 3         // at most this many words per chain
		princeMax      = 5_000_000 // cap on PRINCE candidates per file
		keyWalkMin     = 4         // shortest keyboard walk
		keyWalkMax     = 10        // longest keyboard walk
		keyWalkCount   = 1_000_000 // cap on generated walks
		markovMinLen   = 1         // shortest Markov guess
		markovMaxLen   = 16        // longest Markov guess
	)

	// A fresh, re-iterable chain of the file wordlists (stdin excluded, since it
	// cannot be re-read). Shared by the hybrid, PRINCE and toggle-case builders.
	freshWordlist := func() candidates.Source {
		var ws []candidates.Source
		for _, wl := range allWordlists {
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

	buildCandidates := func(path string) xcrack.CandidateSource {
		var srcs []candidates.Source
		if pcfgModel != nil {
			srcs = append(srcs, pcfgModel.Source(*pcfgMax))
		}
		if markovModel != nil {
			srcs = append(srcs, candidates.MarkovGen(markovModel, markovMinLen, markovMaxLen, *markovMax))
		}
		// Root-name context: the engine derives name candidates for every nested
		// node, but the top-level file's name is only known here, so seed it first.
		if opts.ContextCandidates {
			if names := candidates.FromName(filepath.Base(path)); len(names) > 0 {
				srcs = append(srcs, candidates.Explicit(names...))
			}
		}
		if len(allPasswords) > 0 {
			srcs = append(srcs, candidates.Explicit(allPasswords...))
		}
		if useDefault {
			srcs = append(srcs, candidates.DefaultList())
		}
		// Spray: a compact, high-yield curated/token set, tried early (before the
		// bulk wordlists). Years default to the current/previous calendar year.
		if useSpray {
			srcs = append(srcs, candidates.Spray(sprayTok, sprayYearInts, 0))
		}
		// Breach corpora: frequency-ordered real-leak lists, higher yield than a
		// generic wordlist, so tried ahead of them. Count-annotated lines are
		// parsed (and optionally prevalence-filtered); rules mangle each entry.
		for _, bl := range allBreach {
			base := patternSet.ApplyRules(candidates.BreachFile(bl, breachMin))
			srcs = append(srcs, base)
		}
		for _, wl := range allWordlists {
			var base candidates.Source
			if wl == "-" {
				base = candidates.Stdin()
			} else {
				base = candidates.File(wl)
			}
			// Mangling rules expand each wordlist entry.
			base = patternSet.ApplyRules(base)
			srcs = append(srcs, base)
		}
		// Masks are standalone keyspaces appended after the wordlists. With
		// --increment, each mask spec is expanded into shortest-first prefix masks
		// over the requested token-length range instead of used at full length.
		if incMin > 0 || incMax > 0 {
			for _, spec := range maskSpecs {
				for _, inc := range pattern.ExpandIncrement(spec, incMin, incMax) {
					if m, err := pattern.CompileMask(inc, customCharsets); err == nil {
						srcs = append(srcs, m.Source())
					}
				}
			}
		} else {
			srcs = append(srcs, patternSet.MaskSources()...)
		}
		// Combinator (hashcat -a 1): every left word followed by every right word
		// (optional separator). Built over fresh file readers so each file run is
		// independent.
		if *combLeft != "" && *combRight != "" {
			srcs = append(srcs, candidates.Combinator(candidates.File(*combLeft), candidates.File(*combRight), []byte(*combSep)))
		}
		// Hybrid attacks: each wordlist word combined with every expansion of a
		// mask (dict+mask / mask+dict). Built over a fresh file-wordlist chain
		// (stdin cannot be re-iterated per mask, so it is excluded here).
		if len(hybridAppendMasks) > 0 || len(hybridPrependMasks) > 0 {
			for _, m := range hybridAppendMasks {
				if w := freshWordlist(); w != nil {
					srcs = append(srcs, pattern.Hybrid(w, m, true))
				}
			}
			for _, m := range hybridPrependMasks {
				if w := freshWordlist(); w != nil {
					srcs = append(srcs, pattern.Hybrid(w, m, false))
				}
			}
		}
		// Toggle-case variants of the wordlist words (hashcat toggle attack).
		if genToggle {
			if w := freshWordlist(); w != nil {
				srcs = append(srcs, candidates.ToggleCase(w, 0))
			}
		}
		// PRINCE: length-ordered concatenations of wordlist words.
		if genPrince {
			if w := freshWordlist(); w != nil {
				srcs = append(srcs, candidates.Prince(w, 1, princeMaxLen, princeMaxWords, princeMax))
			}
		}
		// Keyboard-walk: adjacency walks on a QWERTY keyboard (standalone).
		if genKeyWalk {
			srcs = append(srcs, candidates.KeyboardWalk(keyWalkMin, keyWalkMax, keyWalkCount))
		}
		// Distributed cracking: restrict this worker to its stride of the keyspace.
		// A no-op when shardCount <= 1. Promoted/context/hint guesses live outside
		// this base source, so every worker still tries them.
		return candidates.Shard(candidates.Chain(srcs...), shardIndex, shardCount)
	}

	ctx := context.Background()
	pool := xcrack.NewPool(opts)
	defer pool.Close()

	results := make([]*xcrack.Result, len(files))
	errs := make([]error, len(files))
	jobs := opts.FileConcurrency
	if jobs < 1 {
		jobs = 1
	}
	var prog *progress
	if *progressF {
		prog = newProgress(len(files))
	}
	sem := make(chan struct{}, jobs)
	// Dispatch order: argument order by default. With --adaptive, dispatch the
	// smallest files first so the cheap, likely wins surface early and seed the
	// corpus-wide promotion set before the big files run. Results stay indexed by
	// the original position, so output order is unchanged.
	dispatch := make([]int, len(files))
	for i := range files {
		dispatch[i] = i
	}
	if opts.CorpusPromotion {
		sizes := make([]int64, len(files))
		for i, path := range files {
			if fi, err := os.Stat(path); err == nil {
				sizes[i] = fi.Size()
			}
		}
		sort.SliceStable(dispatch, func(a, b int) bool { return sizes[dispatch[a]] < sizes[dispatch[b]] })
	}

	var wg sync.WaitGroup
	for _, i := range dispatch {
		path := files[i]
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, path string) {
			defer wg.Done()
			defer func() { <-sem }()
			if prog != nil {
				defer prog.fileDone()
			}
			data, err := os.ReadFile(path)
			if err != nil {
				errs[i] = err
				return
			}
			src := buildCandidates(path)
			// Resumable single-target run: wrap the candidate source so progress is
			// persisted and an interrupted run resumes near where it stopped.
			if *checkpointPath != "" {
				sig := fmt.Sprintf("%s:%d:%s:shard%d/%d", filepath.Base(path), len(data), candidateSig(allPasswords, allWordlists, allBreach, useDefault, []string(patterns), useSpray, sprayTok), shardIndex, shardCount)
				ck, cerr := candidates.Checkpoint(src, *checkpointPath, sig, 0, -1)
				if cerr != nil {
					errs[i] = cerr
					return
				}
				if rf := ck.(candidates.Resumable).ResumeFrom(); rf > 0 {
					fmt.Fprintf(os.Stderr, "xcrack: resuming from candidate %d (checkpoint %s)\n", rf, *checkpointPath)
				}
				src = ck
			}
			res, err := pool.Process(ctx, bytes.NewReader(data), int64(len(data)), src)
			if err != nil {
				errs[i] = err
				return
			}
			// The target was searched to completion (found or exhausted): persist the
			// final position and clear the checkpoint so a re-run starts fresh.
			if *checkpointPath != "" {
				if s, ok := src.(candidates.Saver); ok {
					s.Save()
				}
				os.Remove(*checkpointPath)
			}
			res.Root.Path = filepath.Base(path)
			results[i] = res
			if prog != nil {
				prog.addCandidates(res.Stats.CandidatesTried)
			}
		}(i, path)
	}
	wg.Wait()
	if prog != nil {
		prog.close()
	}
	// Persist newly recovered passwords to the potfile.
	if pot != nil {
		for _, r := range results {
			if r != nil {
				pot.add(r.Passwords()...)
			}
		}
	}

	return render(files, results, errs, outFormat, *out, resFile)
}

func render(files []string, results []*xcrack.Result, errs []error, outFormat, outDir, resFile string) int {
	exit := 0
	anyDecrypted, anyLocked := false, false
	for i, path := range files {
		if errs[i] != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %s: %v\n", path, errs[i])
			exit = maxInt(exit, 2)
			continue
		}
		res := results[i]
		switch outFormat {
		case "json":
			_ = renderJSON(os.Stdout, res)
		case "jsonl":
			_ = renderJSONL(os.Stdout, res)
		default:
			fmt.Printf("== %s ==\n", path)
			renderText(os.Stdout, res)
			fmt.Println()
		}
		res.Root.Walk(func(n *xcrack.Node) {
			if n.Status == xcrack.StatusDecrypted {
				anyDecrypted = true
			}
			if n.Status == xcrack.StatusLocked {
				anyLocked = true
			}
		})
		if outDir != "" {
			dst := filepath.Join(outDir, filepath.Base(path)+".extracted")
			if err := writeTree(dst, res); err != nil {
				fmt.Fprintf(os.Stderr, "xcrack: write %s: %v\n", dst, err)
				exit = maxInt(exit, 2)
			}
		}
		if resFile != "" {
			f, err := os.OpenFile(resFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err == nil {
				_ = renderJSON(f, res)
				f.Close()
			}
		}
		res.Close() // release any disk-spilled intermediates
	}
	if exit == 2 {
		return 2
	}
	if anyDecrypted {
		return 0
	}
	if anyLocked {
		return 1
	}
	return 0
}

func runIdentify(args []string) int {
	fs_ := flag.NewFlagSet("xcrack identify", flag.ContinueOnError)
	var sources stringSlice
	fs_.Var(&sources, "source", "source file (repeatable)")
	fs_.Var(&sources, "s", "alias for --source")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) == 0 {
		fmt.Fprintln(os.Stderr, "xcrack identify: no sources")
		return 2
	}
	files, err := expandSources(srcArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	reg := xcrack.DefaultRegistry()
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			continue
		}
		peek := data
		if len(peek) > 512 {
			peek = peek[:512]
		}
		f, derr := reg.Detect(peek)
		if derr != nil {
			fmt.Printf("%s: unknown format\n", path)
			continue
		}
		caps := f.Caps()
		fmt.Printf("%s: format=%s container=%v encrypted=%v explodable=%v\n",
			path, f.Name(), caps.Container, caps.Encrypted, caps.Explodable)
	}
	return 0
}

// expandSources turns globs/dirs/files into a flat list of file paths.
func expandSources(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		matches, err := filepath.Glob(a)
		if err != nil {
			return nil, err
		}
		if matches == nil {
			matches = []string{a}
		}
		for _, m := range matches {
			info, err := os.Stat(m)
			if err != nil {
				return nil, err
			}
			if info.IsDir() {
				err := filepath.WalkDir(m, func(p string, d fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					if !d.IsDir() {
						out = append(out, p)
					}
					return nil
				})
				if err != nil {
					return nil, err
				}
			} else {
				out = append(out, m)
			}
		}
	}
	return out, nil
}

// --- precedence helpers ---

func env(key string) string { return os.Getenv(key) }

func resolveInt(flagSet bool, flagVal int, envVal string, cfgVal, def int) int {
	if flagSet && flagVal != 0 {
		return flagVal
	}
	if envVal != "" {
		var n int
		if _, err := fmt.Sscanf(envVal, "%d", &n); err == nil && n != 0 {
			return n
		}
	}
	if cfgVal != 0 {
		return cfgVal
	}
	return def
}

func resolveInt64(flagSet bool, flagVal, cfgVal, def int64) int64 {
	if flagSet && flagVal != 0 {
		return flagVal
	}
	if cfgVal != 0 {
		return cfgVal
	}
	return def
}

func cfgInt(c *fileConfig, f func(*fileConfig) int) int {
	if c == nil {
		return 0
	}
	return f(c)
}
func cfgInt64(c *fileConfig, f func(*fileConfig) int64) int64 {
	if c == nil {
		return 0
	}
	return f(c)
}
func cfgStr(c *fileConfig, f func(*fileConfig) string) string {
	if c == nil {
		return ""
	}
	return f(c)
}
func flagIf(set bool, v string) string {
	if set {
		return v
	}
	return ""
}
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func usage() {
	fmt.Fprint(os.Stderr, `xcrack `+version+` -- recover access to password-protected / encrypted files

USAGE:
  xcrack [flags] [sources...]      decrypt and recursively decompose sources
  xcrack identify [sources...]     detect format & encryption only
  xcrack kp --plain P --cipher C   ZipCrypto known-plaintext key recovery
                                   (no password; --bkcrack offloads the search)
  xcrack hashline [sources...]     emit $office$/$pdf$/... lines for hashcat/John
  xcrack version

COMMON FLAGS:
  -s, --source PATH         source file/dir/glob (repeatable)
  -o, --out DIR             write decrypted tree to DIR
  -w, --wordlist FILE       wordlist (repeatable; - = stdin; gzip ok)
  -p, --password STR        explicit candidate (repeatable)
  -c, --config FILE         YAML config
      --format text|json|jsonl
      --workers N  --file-jobs N  --max-procs N
      --timeout D  --max-duration D  --batch-size N  --throttle PCT
      --context                  derive guesses from names + plain siblings
      --hint                     derive guesses from an embedded password hint
      --hint-rules FILE          rule file applied to hint-derived words
      --hybrid-append MASK       wordlist word + mask expansion (dict+mask; repeatable)
      --hybrid-prepend MASK      mask expansion + wordlist word (mask+dict; repeatable)
      --toggle-case              also try case-toggle variants of each wordlist word
      --prince                   also try PRINCE chains (concatenated wordlist words)
      --keyboard-walk            also try QWERTY keyboard-adjacency walks
      --markov                   generate best-first guesses from a Markov model (--markov-max N)
      --increment MIN:MAX        expand each mask over a token-length range, shortest first
      --combinator-left FILE --combinator-right FILE [--combinator-sep S]   combinator attack
      --as SCHEME                force a scheme for a magic-less file (e.g. sqlcipher)
      --shard I/N                distributed cracking: test only shard I of N of the keyspace
      --adaptive                 corpus-wide promotion: reuse found passwords across files, smallest first
      --spray                    curated spray set (common + season/year), tried early
      --spray-token STR          org/product/user token mangled into the spray set (repeatable)
      --spray-year N             year used in spray patterns (repeatable; default current/previous)
      --breach FILE              frequency-annotated breach corpus (count-prefixed or pw:count; repeatable)
      --breach-min-count N       drop breach entries seen fewer than N times
      --recurse / --no-recurse   --explode-documents
      --max-depth N  --max-total-bytes N  --max-nodes N
      --no-default-list
      --results-file FILE

Authorized use only: operate on files you own or are permitted to access.
`)
}

// buildPatternSet merges the pattern-file DSL (--pattern) and the config's
// patterns block into one compiled pattern.Set (masks + rules + custom charsets).
// buildHintRules compiles the hint-mangling ruleset from the --hint-rules file
// (hashcat-style, one rule per line) plus any inline rules in the config, and
// returns a word->variants function for Options.HintRules. It returns nil when
// there are no rules, so only the hint-derived base words are tried.
func buildHintRules(file string, cfg *fileConfig) (func(string) []string, error) {
	var lines []string
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		lines = append(lines, strings.Split(string(data), "\n")...)
	}
	if cfg != nil {
		lines = append(lines, cfg.Search.HintRules...)
	}
	rs, err := pattern.CompileRules(lines)
	if err != nil {
		return nil, err
	}
	if rs.Len() == 0 {
		return nil, nil
	}
	return func(base string) []string {
		mangled := rs.Apply([]byte(base))
		out := make([]string, 0, len(mangled))
		for _, v := range mangled {
			out = append(out, string(v))
		}
		return out
	}, nil
}

func buildPatternSet(files []string, cfg *fileConfig) (*pattern.Set, map[rune]string, []string, error) {
	spec := pattern.Spec{CustomCharsets: map[rune]string{}}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, nil, err
		}
		s, err := pattern.ParseText(data)
		if err != nil {
			return nil, nil, nil, err
		}
		spec.Masks = append(spec.Masks, s.Masks...)
		spec.Rules = append(spec.Rules, s.Rules...)
		for k, v := range s.CustomCharsets {
			spec.CustomCharsets[k] = v
		}
	}
	if cfg != nil {
		spec.Masks = append(spec.Masks, cfg.Patterns.Masks...)
		spec.Rules = append(spec.Rules, cfg.Patterns.Rules...)
		for k, v := range cfg.Patterns.CustomCharsets {
			if len(k) == 1 {
				spec.CustomCharsets[rune(k[0])] = v
			}
		}
	}
	set, err := pattern.Compile(spec)
	return set, spec.CustomCharsets, spec.Masks, err
}

// compileMasks compiles each mask spec (sharing the custom charset table) for a
// hybrid attack, failing on the first malformed mask.
func compileMasks(specs []string, custom map[rune]string) ([]*pattern.Mask, error) {
	var out []*pattern.Mask
	for _, s := range specs {
		m, err := pattern.CompileMask(s, custom)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}
