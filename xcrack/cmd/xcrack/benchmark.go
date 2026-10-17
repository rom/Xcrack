package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"sort"
	"strconv"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats"
)

// costOrder ranks files weakest / fastest-attack-first for the automatic cost
// queue: it probes each file and measures its per-format verify rate over a
// short window, then returns dispatch indices sorted by rate descending (fast,
// weak schemes — ZipCrypto, legacy Office, low-iteration KDFs — first; slow,
// strong KDFs later; unencrypted or unsupported files last). All files share the
// same candidate set, so the per-format rate is the differentiator and ranking
// can use a short window. The order is stable among equal-rate files, preserving
// argument order as a tie-break.
func costOrder(files []string, reg *xfileformats.Registry, window time.Duration) []int {
	rates := make([]float64, len(files))
	for i, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			rates[i] = -1 // unreadable: dispatch last
			continue
		}
		_, verify, ok := firstTarget(reg, data)
		if !ok {
			rates[i] = -1 // not encrypted / unsupported: dispatch last
			continue
		}
		rates[i] = measureRate(verify, window)
	}
	idx := make([]int, len(files))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool { return rates[idx[a]] > rates[idx[b]] })
	return idx
}

// previewPath returns a representative path for the candidate-only modes
// (--stdout/--keyspace): the first source if any, else "" (the candidate stream
// does not depend on file content for those modes).
func previewPath(files []string) string {
	if len(files) > 0 {
		return files[0]
	}
	return ""
}

// runStdout prints the candidate stream to stdout without cracking (hashcat
// --stdout): the fully-assembled wordlists + rules + masks + generators, one per
// line, up to limit (0 = no cap). It is the way to see exactly what a given set
// of flags would try.
func runStdout(build func(string) xcrack.CandidateSource, path string, limit int64) int {
	src := build(path)
	if src == nil {
		fmt.Fprintln(os.Stderr, "xcrack --stdout: no candidate sources (give -w/-p/--pattern/generators)")
		return 2
	}
	if err := src.Reset(); err != nil {
		fmt.Fprintf(os.Stderr, "xcrack --stdout: %v\n", err)
		return 2
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	var n int64
	for limit <= 0 || n < limit {
		pw, err := src.Next()
		if err != nil {
			break
		}
		w.Write(pw)
		w.WriteByte('\n')
		n++
	}
	return 0
}

// runKeyspace prints the candidate keyspace size without cracking (hashcat
// --keyspace). A source with a known length (masks, explicit lists, the Swedish
// list) reports instantly and exactly; an unknown-length source (a wordlist,
// rule expansion, a generator) is counted by iterating, bounded by limit so a
// huge mixed keyspace cannot hang — then reported as ">= N (capped)".
func runKeyspace(build func(string) xcrack.CandidateSource, path string, limit int64) int {
	src := build(path)
	if src == nil {
		fmt.Fprintln(os.Stderr, "xcrack --keyspace: no candidate sources (give -w/-p/--pattern/generators)")
		return 2
	}
	if n := src.Len(); n >= 0 {
		fmt.Println(n)
		return 0
	}
	n, capped := countKeyspace(src, limit)
	if capped {
		fmt.Printf(">=%d (capped; pass --limit to count further)\n", n)
	} else {
		fmt.Println(n)
	}
	return 0
}

// countKeyspace counts the candidates a source yields, stopping at cap (0 = no
// cap). It returns the count and whether the cap was hit.
func countKeyspace(src candidates.Source, cap int64) (int64, bool) {
	if err := src.Reset(); err != nil {
		return 0, false
	}
	var n int64
	for {
		if cap > 0 && n >= cap {
			return n, true
		}
		if _, err := src.Next(); err != nil {
			return n, false
		}
		n++
	}
}

// runBenchmark measures the password-verification rate for each source file's
// format (hashcat -b): it probes the file, then hammers the real verifier with
// distinct wrong candidates for a fixed window and reports candidates/second —
// the number you need to turn a keyspace into a time estimate.
func runBenchmark(files []string, reg *xfileformats.Registry) int {
	exit := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %s: %v\n", path, err)
			exit = 2
			continue
		}
		label, verify, ok := firstTarget(reg, data)
		if !ok {
			fmt.Printf("%s  [not encrypted or unsupported — nothing to benchmark]\n", path)
			continue
		}
		rate := measureRate(verify, 2*time.Second)
		fmt.Printf("%s  [%s] %s candidates/sec\n", path, label, humanRate(rate))
	}
	return exit
}

// runEstimate reports, per source file, the keyspace of the configured candidate
// set, the measured verify rate for that file's format, and the resulting
// time-to-exhaust (and expected ~half that to a hit) — the "how long will this
// take" answer.
func runEstimate(files []string, reg *xfileformats.Registry, build func(string) xcrack.CandidateSource) int {
	exit := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %s: %v\n", path, err)
			exit = 2
			continue
		}
		label, verify, ok := firstTarget(reg, data)
		if !ok {
			fmt.Printf("%s  [not encrypted or unsupported]\n", path)
			continue
		}
		rate := measureRate(verify, 1500*time.Millisecond)

		var ksText string
		var ks int64 = -1
		var capped bool
		src := build(path)
		if src != nil {
			if n := src.Len(); n >= 0 {
				ks = n
			} else {
				ks, capped = countKeyspace(src, 50_000_000)
			}
		}
		if ks < 0 {
			ksText = "unknown"
		} else if capped {
			ksText = fmt.Sprintf(">=%d", ks)
		} else {
			ksText = strconv.FormatInt(ks, 10)
		}

		fmt.Printf("%s  [%s]\n", path, label)
		fmt.Printf("    rate      %s candidates/sec\n", humanRate(rate))
		fmt.Printf("    keyspace  %s\n", ksText)
		if ks >= 0 && rate > 0 {
			worst := time.Duration(float64(ks) / rate * float64(time.Second))
			avg := time.Duration(float64(ks) / (2 * rate) * float64(time.Second))
			note := ""
			if capped {
				note = " (keyspace capped at the count limit; true time is larger)"
			}
			fmt.Printf("    time      ~%s to exhaust, ~%s expected to a hit%s\n", roundDur(worst), roundDur(avg), note)
		} else {
			fmt.Printf("    time      unknown (keyspace or rate unavailable)\n")
		}
	}
	return exit
}

// firstTarget probes data and returns a label plus a single-password verifier
// for the first encrypted target: a whole-file encrypted format, or the first
// encrypted entry of a container. ok is false when nothing encrypted is found.
// Parsing runs under a recover guard so a malformed file yields ok=false rather
// than a panic.
func firstTarget(reg *xfileformats.Registry, data []byte) (label string, verify func([]byte) (bool, error), ok bool) {
	defer func() {
		if recover() != nil {
			label, verify, ok = "", nil, false
		}
	}()
	r := bytes.NewReader(data)
	size := int64(len(data))
	for _, cand := range reg.DetectAll(peekBytes(data)) {
		caps := cand.Caps()
		if enc, isEnc := cand.(xfileformats.Encrypted); isEnc && caps.Encrypted {
			ch, perr := enc.Probe(r, size)
			if perr != nil || ch == nil {
				continue
			}
			scheme := schemeName(ch, cand.Name())
			return scheme, func(pw []byte) (bool, error) {
				okv, _, verr := enc.Verify(ch, pw)
				return okv, verr
			}, true
		}
		if cont, isCont := cand.(xfileformats.Container); isCont && caps.Container {
			entries, eerr := cont.Entries(r, size)
			if eerr != nil {
				continue
			}
			for _, e := range entries {
				if e != nil && e.Encrypted && e.Verify != nil {
					return schemeName(e.Challenge, cand.Name()), e.Verify, true
				}
			}
			return "", nil, false
		}
	}
	return "", nil, false
}

func schemeName(ch *xcrypto.Challenge, fallback string) string {
	if ch != nil && ch.Scheme != "" {
		return ch.Scheme
	}
	return fallback
}

// measureRate runs verify against distinct wrong candidates for window and
// returns the observed candidates/second. A short warmup is included in the
// window; the candidates are unique so the KDF genuinely runs each time.
func measureRate(verify func([]byte) (bool, error), window time.Duration) float64 {
	deadline := time.Now().Add(window)
	start := time.Now()
	var n int64
	buf := make([]byte, 0, 24)
	for {
		buf = append(buf[:0], "xcrackbench-"...)
		buf = strconv.AppendInt(buf, n, 10)
		func() {
			defer func() { _ = recover() }() // a hostile verifier must not crash the benchmark
			verify(append([]byte(nil), buf...))
		}()
		n++
		if n%16 == 0 && time.Now().After(deadline) {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		return 0
	}
	return float64(n) / elapsed
}

func humanRate(r float64) string {
	switch {
	case r >= 1e9:
		return fmt.Sprintf("%.2fG", r/1e9)
	case r >= 1e6:
		return fmt.Sprintf("%.2fM", r/1e6)
	case r >= 1e3:
		return fmt.Sprintf("%.2fk", r/1e3)
	default:
		return fmt.Sprintf("%.0f", r)
	}
}

// roundDur rounds a duration to a human-friendly precision and caps the display
// at a readable magnitude (years) for astronomically large keyspaces.
func roundDur(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	const year = 365 * 24 * time.Hour
	years := float64(d) / float64(year)
	if years > 1000 {
		return fmt.Sprintf("%.2g years", years)
	}
	switch {
	case d >= year:
		return fmt.Sprintf("%.1f years", years)
	case d >= 24*time.Hour:
		return fmt.Sprintf("%.1f days", d.Hours()/24)
	case d >= time.Hour:
		return d.Round(time.Minute).String()
	case d >= time.Minute:
		return d.Round(time.Second).String()
	default:
		return d.Round(10 * time.Millisecond).String()
	}
}
