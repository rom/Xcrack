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
	"strings"
	"sync"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrack/pkg/xcrack/candidates"
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

	recurse := fs_.Bool("recurse", true, "decompose containers")
	noRecurse := fs_.Bool("no-recurse", false, "disable container decomposition")
	explode := fs_.Bool("explode-documents", false, "decompose documents into internal parts")
	noDefault := fs_.Bool("no-default-list", false, "disable the built-in common-password list")
	findAll := fs_.Bool("find-all", false, "keep searching after first match (phase 2; ignored)")

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

	opts.Limits = xcrack.DefaultLimits()
	opts.Limits.MaxDepth = resolveInt(set["max-depth"], *maxDepth, "", cfgInt(cfg, func(c *fileConfig) int { return c.Limits.MaxDepth }), opts.Limits.MaxDepth)
	opts.Limits.MaxTotalBytes = resolveInt64(set["max-total-bytes"], *maxTotal, cfgInt64(cfg, func(c *fileConfig) int64 { return c.Limits.MaxTotalBytes }), opts.Limits.MaxTotalBytes)
	opts.Limits.MaxNodes = resolveInt(set["max-nodes"], *maxNodes, "", cfgInt(cfg, func(c *fileConfig) int { return c.Limits.MaxNodes }), opts.Limits.MaxNodes)
	opts.Limits.MaxEntrySize = resolveInt64(set["max-entry-size"], *maxEntry, cfgInt64(cfg, func(c *fileConfig) int64 { return c.Limits.MaxEntrySize }), opts.Limits.MaxEntrySize)
	opts.Limits.MaxCandidates = resolveInt64(set["max-candidates"], *maxCand, cfgInt64(cfg, func(c *fileConfig) int64 { return c.Limits.MaxCandidates }), 0)

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
	_ = logLevel // reserved: structured logging wiring is phase 2

	if len(patterns) > 0 {
		fmt.Fprintln(os.Stderr, "xcrack: warning: --pattern is not yet implemented (phase 2); ignoring")
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

	// candidate builder (fresh per file; sources are stateful and used concurrently)
	useDefault := !*noDefault
	if cfg != nil && cfg.Candidates.UseDefaultList != nil {
		useDefault = *cfg.Candidates.UseDefaultList
	}
	cfgPasswords, cfgWordlists := []string(nil), []string(nil)
	if cfg != nil {
		cfgPasswords = cfg.Candidates.Passwords
		cfgWordlists = cfg.Candidates.Wordlists
	}
	allPasswords := append(append([]string{}, passwords...), cfgPasswords...)
	allWordlists := append(append([]string{}, wordlists...), cfgWordlists...)
	buildCandidates := func() xcrack.CandidateSource {
		var srcs []candidates.Source
		if len(allPasswords) > 0 {
			srcs = append(srcs, candidates.Explicit(allPasswords...))
		}
		if useDefault {
			srcs = append(srcs, candidates.DefaultList())
		}
		for _, wl := range allWordlists {
			if wl == "-" {
				srcs = append(srcs, candidates.Stdin())
			} else {
				srcs = append(srcs, candidates.File(wl))
			}
		}
		return candidates.Chain(srcs...)
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
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	for i, path := range files {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, path string) {
			defer wg.Done()
			defer func() { <-sem }()
			data, err := os.ReadFile(path)
			if err != nil {
				errs[i] = err
				return
			}
			res, err := pool.Process(ctx, bytes.NewReader(data), int64(len(data)), buildCandidates())
			if err != nil {
				errs[i] = err
				return
			}
			res.Root.Path = filepath.Base(path)
			results[i] = res
		}(i, path)
	}
	wg.Wait()

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
  xcrack version

COMMON FLAGS:
  -s, --source PATH         source file/dir/glob (repeatable)
  -o, --out DIR             write decrypted tree to DIR
  -w, --wordlist FILE       wordlist (repeatable; - = stdin; gzip ok)
  -p, --password STR        explicit candidate (repeatable)
  -c, --config FILE         YAML config
      --format text|json|jsonl
      --workers N  --file-jobs N  --max-procs N
      --timeout D  --max-duration D
      --recurse / --no-recurse   --explode-documents
      --max-depth N  --max-total-bytes N  --max-nodes N
      --no-default-list
      --results-file FILE

Authorized use only: operate on files you own or are permitted to access.
`)
}
