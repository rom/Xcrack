package jobspec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/pattern"
	"github.com/rom/xfileformats"
)

// parseDuration parses a Go duration string; the empty string means "unset" (0).
func parseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	return time.ParseDuration(s)
}

// parseShard parses a "I/N" shard spec into a zero-based index and a count. An
// empty spec means no sharding (index 0, count 1). A malformed spec or an
// out-of-range index is rejected so a mistyped shard can never silently skip
// part of the keyspace.
func parseShard(spec string) (index, count int, err error) {
	if strings.TrimSpace(spec) == "" {
		return 0, 1, nil
	}
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("want I/N (e.g. 0/4), got %q", spec)
	}
	i, ierr := strconv.Atoi(strings.TrimSpace(parts[0]))
	n, nerr := strconv.Atoi(strings.TrimSpace(parts[1]))
	if ierr != nil || nerr != nil {
		return 0, 0, fmt.Errorf("want integers I/N, got %q", spec)
	}
	if n < 1 {
		return 0, 0, fmt.Errorf("shard count must be >= 1, got %d", n)
	}
	if i < 0 || i >= n {
		return 0, 0, fmt.Errorf("shard index %d out of range for count %d (want 0..%d)", i, n, n-1)
	}
	return i, n, nil
}

// parseIncrement parses a "MIN:MAX" (or "MIN", or "MIN-MAX") increment spec into
// min/max token lengths. The empty string means no incrementing (0, 0).
func parseIncrement(spec string) (min, max int, err error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return 0, 0, nil
	}
	sep := ":"
	if !strings.Contains(spec, ":") && strings.Contains(spec, "-") {
		sep = "-"
	}
	parts := strings.SplitN(spec, sep, 2)
	min, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || min < 1 {
		return 0, 0, fmt.Errorf("want MIN[:MAX] with MIN>=1, got %q", spec)
	}
	max = min
	if len(parts) == 2 {
		max, err = strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || max < min {
			return 0, 0, fmt.Errorf("want MIN:MAX with MAX>=MIN, got %q", spec)
		}
	}
	return min, max, nil
}

// parseEncodingName validates a candidate-encoding name, returning the resolved
// encoding. It is used by Validate so a bad name fails before a job starts.
func parseEncodingName(name string) (candidates.Encoding, error) {
	return candidates.ParseEncoding(name)
}

// forceRegistry resolves an --as/input.as force-format name to a registry that
// contains only that format. ok is false for an unknown name.
func forceRegistry(name string) (*xfileformats.Registry, bool) {
	return xcrack.ForceRegistry(name)
}

// buildHintRules compiles the hint-mangling ruleset from inline hashcat-style
// rule lines. It returns nil (so only the hint-derived base words are tried)
// when there are no rules.
func buildHintRules(lines []string) (func(string) []string, error) {
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

// buildPatternSet compiles the Patterns block (inline masks, rules and custom
// charsets) plus any generated rules into one pattern.Set, returning the set,
// the resolved custom-charset table and the mask specs (for --increment
// expansion).
func buildPatternSet(s *Spec, extraRules []string) (*pattern.Set, map[rune]string, []string, error) {
	spec := pattern.Spec{CustomCharsets: map[rune]string{}}
	spec.Masks = append(spec.Masks, s.Patterns.Masks...)
	spec.Rules = append(spec.Rules, s.Patterns.Rules...)
	for k, v := range s.Patterns.CustomCharsets {
		if len(k) == 1 {
			spec.CustomCharsets[rune(k[0])] = v
		}
	}
	spec.Rules = append(spec.Rules, extraRules...)
	set, err := pattern.Compile(spec)
	return set, spec.CustomCharsets, spec.Masks, err
}

// compileMasks compiles each mask spec (sharing the custom charset table),
// failing on the first malformed mask.
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

// passwordsFromFiles reads candidate passwords (one per line) from each file.
func passwordsFromFiles(paths []string) ([]string, error) {
	var out []string
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			out = append(out, strings.TrimRight(sc.Text(), "\r\n"))
		}
		cerr := sc.Err()
		f.Close()
		if cerr != nil {
			return nil, cerr
		}
	}
	return out, nil
}

// collectTrainingWords gathers a bounded corpus to train a PCFG/Markov model on:
// the explicit passwords, the built-in common-password list (if enabled), and
// the lines of each wordlist file (stdin "-" is skipped — it is consumed by the
// search itself). At most max words are returned.
func collectTrainingWords(explicit []string, useDefault bool, wordlists []string, max int) []string {
	out := make([]string, 0, len(explicit))
	add := func(s string) bool {
		if s == "" {
			return true
		}
		out = append(out, s)
		return len(out) < max
	}
	for _, p := range explicit {
		if !add(p) {
			return out
		}
	}
	if useDefault {
		src := candidates.DefaultList()
		for {
			b, err := src.Next()
			if err == io.EOF || err != nil {
				break
			}
			if !add(string(b)) {
				return out
			}
		}
	}
	for _, wl := range wordlists {
		if wl == "-" {
			continue
		}
		f, err := os.Open(wl)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			if !add(strings.TrimRight(sc.Text(), "\r\n")) {
				f.Close()
				return out
			}
		}
		f.Close()
	}
	return out
}

// trainingSamples is collectTrainingWords as a [][]byte for the Markov trainers.
func trainingSamples(explicit []string, useDefault bool, wordlists []string) [][]byte {
	words := collectTrainingWords(explicit, useDefault, wordlists, trainingWordCap)
	samples := make([][]byte, len(words))
	for i, w := range words {
		samples[i] = []byte(w)
	}
	return samples
}
