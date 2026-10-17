package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// confView is a secrets-free snapshot of the effective configuration after
// merging flags, environment, the config file and defaults. --show-config
// prints it. It carries only counts for candidate passwords (never the values),
// so it is safe to paste into a bug report; the found-cache path is shown, its
// contents are not (use --show-cache for those).
type confView struct {
	Sources []string

	Workers, FileJobs, MaxProcs, BatchSize, Throttle int

	MaxDepth, MaxNodes                         int
	MaxTotalBytes, MaxEntrySize, MaxCandidates int64

	Recurse, Explode                          bool
	Promote, FindAll, Adaptive, Context, Hint bool

	UseDefaultList, Swedish  bool
	Wordlists, Breach        []string
	PasswordCount            int
	Spray, CostQueue, Markov bool
	Order, Shard, Encoding   string
	MinLen, MaxLen           int

	FoundCache string
	Loopback   bool

	Masks     []string
	RuleCount int
	HCMask    []string

	Format, ResultsFile, LogLevel, OutDir, ExtractSuffix string

	PerFile, Total time.Duration

	Servers     []string
	ClusterMode string
}

func runShowConfig(v confView) int {
	v.print(os.Stdout)
	return 0
}

func (v confView) print(w io.Writer) {
	kv := func(k, val string) { fmt.Fprintf(w, "  %-20s %s\n", k+":", val) }

	fmt.Fprintln(w, "# Effective xcrack configuration (precedence: flags > env > config file > defaults)")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "sources: %s\n", listOr(v.Sources))

	fmt.Fprintln(w, "output:")
	kv("format", v.Format)
	kv("out-dir", strOr(v.OutDir, "(none — report only)"))
	kv("extract-suffix", strOr(v.ExtractSuffix, "(none)"))
	kv("results-file", strOr(v.ResultsFile, "(none)"))
	kv("log-level", v.LogLevel)

	fmt.Fprintln(w, "concurrency:")
	kv("workers", autoNum(v.Workers))
	kv("file-jobs", autoNum(v.FileJobs))
	kv("max-procs", autoNum(v.MaxProcs))
	if v.BatchSize <= 0 {
		kv("batch-size", "0 (auto)")
	} else {
		kv("batch-size", fmt.Sprintf("%d", v.BatchSize))
	}
	kv("throttle", pctOr(v.Throttle))

	fmt.Fprintln(w, "limits:")
	kv("max-depth", fmt.Sprintf("%d", v.MaxDepth))
	kv("max-total-bytes", bytesOr(v.MaxTotalBytes))
	kv("max-entry-size", bytesOr(v.MaxEntrySize))
	kv("max-nodes", unlimitedNum(v.MaxNodes))
	kv("max-candidates", unlimitedNum64(v.MaxCandidates))

	fmt.Fprintln(w, "recursion:")
	kv("recurse", onOff(v.Recurse))
	kv("explode-documents", onOff(v.Explode))

	fmt.Fprintln(w, "search:")
	kv("promote-passwords", onOff(v.Promote))
	kv("find-all", onOff(v.FindAll))
	kv("adaptive", onOff(v.Adaptive))
	kv("context", onOff(v.Context))
	kv("hint", onOff(v.Hint))
	kv("spray", onOff(v.Spray))
	kv("cost-queue", onOff(v.CostQueue))
	kv("markov", onOff(v.Markov))
	kv("order", strOr(v.Order, "(file order)"))
	kv("shard", strOr(v.Shard, "(none)"))
	kv("min-length", fmt.Sprintf("%d", v.MinLen))
	kv("max-length", unlimitedNum(v.MaxLen))
	kv("encoding", strOr(v.Encoding, "utf-8 (default)"))

	fmt.Fprintln(w, "candidates:")
	kv("default-list", onOff(v.UseDefaultList))
	kv("swedish", onOff(v.Swedish))
	kv("wordlists", listOr(v.Wordlists))
	kv("breach", listOr(v.Breach))
	kv("explicit-passwords", fmt.Sprintf("%d (values hidden)", v.PasswordCount))
	kv("found-cache", strOr(v.FoundCache, "(none)"))
	kv("loopback", onOff(v.Loopback))

	fmt.Fprintln(w, "patterns:")
	kv("masks", listOr(v.Masks))
	kv("rules", fmt.Sprintf("%d", v.RuleCount))
	kv("hcmask", listOr(v.HCMask))

	fmt.Fprintln(w, "budget:")
	kv("per-file", durOr(v.PerFile))
	kv("total", durOr(v.Total))

	fmt.Fprintln(w, "cluster:")
	kv("servers", listOr(v.Servers))
	kv("mode", strOr(v.ClusterMode, "(none — local)"))
}

// runShowCache lists the passwords held in the found-password cache / potfile.
// Unlike --show (which reports which files the cache solves), this prints the
// cache contents themselves.
func runShowCache(potPath string, pot *potfile) int {
	if potPath == "" || pot == nil {
		fmt.Fprintln(os.Stderr, "xcrack: no found-password cache configured "+
			"(use --found-cache FILE, --remember, or --potfile FILE)")
		return 1
	}
	pws := pot.passwords()
	fmt.Printf("# found-password cache: %s\n", potPath)
	fmt.Printf("# %d cached password(s)\n", len(pws))
	for _, pw := range pws {
		fmt.Println(pw)
	}
	return 0
}

// --- small formatting helpers ---

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func strOr(s, dflt string) string {
	if s == "" {
		return dflt
	}
	return s
}

func listOr(xs []string) string {
	if len(xs) == 0 {
		return "(none)"
	}
	return strings.Join(xs, ", ")
}

func autoNum(n int) string {
	if n <= 0 {
		return "0 (auto: NumCPU)"
	}
	return fmt.Sprintf("%d", n)
}

func unlimitedNum(n int) string {
	if n <= 0 {
		return "0 (unlimited)"
	}
	return fmt.Sprintf("%d", n)
}

func unlimitedNum64(n int64) string {
	if n <= 0 {
		return "0 (unlimited)"
	}
	return fmt.Sprintf("%d", n)
}

func pctOr(n int) string {
	if n <= 0 {
		return "off"
	}
	return fmt.Sprintf("%d%%", n)
}

func durOr(d time.Duration) string {
	if d <= 0 {
		return "none"
	}
	return d.String()
}

func bytesOr(n int64) string {
	if n <= 0 {
		return "0 (unlimited)"
	}
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB (%d)", float64(n)/float64(div), "KMGTPE"[exp], n)
}
