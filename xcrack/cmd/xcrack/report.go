package main

import (
	"fmt"
	"os"

	"github.com/rom/xcrypto/pattern"
	"github.com/rom/xfileformats"
)

// runDebugRules implements `--debug-rules`: apply the --pattern mangling rules
// to the configured wordlist words and report, per rule, how many words it kept
// vs rejected, plus a few sample transforms — the way hashcat's --debug-mode
// lets you tune a rule file before committing a long run. It cracks nothing.
func runDebugRules(rs *pattern.RuleSet, wordlists []string, useDefault bool, explicit []string) int {
	if rs == nil || rs.Len() == 0 {
		fmt.Fprintln(os.Stderr, "xcrack --debug-rules: no rules (give a --pattern file with rule lines)")
		return 2
	}
	const maxWords = 100000
	words := collectTrainingWords(explicit, useDefault, wordlists, maxWords)
	if len(words) == 0 {
		fmt.Fprintln(os.Stderr, "xcrack --debug-rules: no words (give -w/-p or keep the default list)")
		return 2
	}
	lines := rs.RuleLines()
	kept := make([]int, len(lines))
	rejected := make([]int, len(lines))
	const sampleWords = 3
	for wi, w := range words {
		dbg := rs.ApplyDebug([]byte(w))
		for ri, d := range dbg {
			if d.Kept {
				kept[ri]++
				if wi < sampleWords {
					fmt.Printf("  %-16q %q -> %q\n", lines[ri], w, string(d.Output))
				}
			} else {
				rejected[ri]++
			}
		}
	}
	fmt.Printf("\nrule accounting over %d words:\n", len(words))
	for ri, line := range lines {
		pct := 100.0 * float64(kept[ri]) / float64(len(words))
		fmt.Printf("  %-20q kept=%-8d rejected=%-8d (%.1f%% kept)\n", line, kept[ri], rejected[ri], pct)
	}
	return 0
}

// runShowLeft implements `--show` / `--left`: report which source files are
// already solved by the found-password cache / potfile, without cracking. For
// each file it probes the first encrypted target and tests only the cached
// passwords against it. With left=false (--show) it prints "file:password" for
// every solved file; with left=true (--left) it prints the path of every file
// the cache does NOT solve. Files that are not encrypted / not supported are
// reported on stderr and counted as unsolved.
func runShowLeft(files []string, reg *xfileformats.Registry, pot *potfile, left bool) int {
	var cached []string
	if pot != nil {
		cached = pot.passwords()
	}
	exit := 0
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %s: %v\n", path, err)
			exit = 2
			continue
		}
		_, verify, ok := firstTarget(reg, data)
		if !ok {
			fmt.Fprintf(os.Stderr, "%s: not encrypted or unsupported\n", path)
			if left {
				fmt.Println(path)
			}
			continue
		}
		hit := ""
		for _, pw := range cached {
			if okv, verr := verify([]byte(pw)); verr == nil && okv {
				hit = pw
				break
			}
		}
		switch {
		case hit != "" && !left:
			fmt.Printf("%s:%s\n", path, hit)
		case hit == "" && left:
			fmt.Println(path)
		}
	}
	return exit
}
