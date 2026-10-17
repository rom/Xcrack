package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// runWordlist implements `xcrack wordlist` — small wordlist maintenance utilities
// (the hashcat-utils rli/splitlen niche): length-filter, dedupe, sort, and split.
// It reads the given files (or stdin with no files / "-"), applies the requested
// transforms in a fixed order (length filter → dedupe → sort), then writes to
// --out / stdout, or splits into fixed-size chunks with --split.
func runWordlist(args []string) int {
	fs_ := flag.NewFlagSet("xcrack wordlist", flag.ContinueOnError)
	dedupe := fs_.Bool("dedupe", false, "drop duplicate lines (keep first occurrence)")
	doSort := fs_.Bool("sort", false, "sort lines lexicographically")
	sortLen := fs_.Bool("sort-length", false, "sort by length, then lexicographically (implies --sort)")
	minLen := fs_.Int("min-length", 0, "drop lines shorter than N characters")
	maxLen := fs_.Int("max-length", 0, "drop lines longer than N characters (0 = no max)")
	out := fs_.String("out", "", "write output here (default stdout); ignored with --split")
	split := fs_.Int("split", 0, "split output into chunks of N lines each, written as PREFIX.000, PREFIX.001, …")
	prefix := fs_.String("out-prefix", "part", "filename prefix for --split chunks")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	if *split < 0 {
		fmt.Fprintln(os.Stderr, "xcrack wordlist: --split must be >= 0")
		return 2
	}

	// Read all input lines (files, or stdin when none / "-").
	var lines []string
	readFrom := func(f *os.File) error {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		return sc.Err()
	}
	inputs := fs_.Args()
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	for _, in := range inputs {
		if in == "-" {
			if err := readFrom(os.Stdin); err != nil {
				fmt.Fprintf(os.Stderr, "xcrack wordlist: stdin: %v\n", err)
				return 1
			}
			continue
		}
		f, err := os.Open(in)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
			return 2
		}
		err = readFrom(f)
		f.Close()
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack wordlist: %s: %v\n", in, err)
			return 1
		}
	}

	// 1. length filter (count runes, like a password length).
	if *minLen > 0 || *maxLen > 0 {
		kept := lines[:0]
		for _, l := range lines {
			n := len([]rune(l))
			if n < *minLen {
				continue
			}
			if *maxLen > 0 && n > *maxLen {
				continue
			}
			kept = append(kept, l)
		}
		lines = kept
	}
	// 2. dedupe (preserve first-seen order).
	if *dedupe {
		seen := make(map[string]struct{}, len(lines))
		kept := lines[:0]
		for _, l := range lines {
			if _, ok := seen[l]; ok {
				continue
			}
			seen[l] = struct{}{}
			kept = append(kept, l)
		}
		lines = kept
	}
	// 3. sort.
	if *sortLen {
		sort.SliceStable(lines, func(a, b int) bool {
			la, lb := len([]rune(lines[a])), len([]rune(lines[b]))
			if la != lb {
				return la < lb
			}
			return lines[a] < lines[b]
		})
	} else if *doSort {
		sort.Strings(lines)
	}

	// Output: split into chunks, or a single destination.
	if *split > 0 {
		for i, n := 0, 0; i < len(lines); i, n = i+*split, n+1 {
			end := i + *split
			if end > len(lines) {
				end = len(lines)
			}
			name := fmt.Sprintf("%s.%03d", *prefix, n)
			if err := os.WriteFile(name, []byte(strings.Join(lines[i:end], "\n")+"\n"), 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "xcrack wordlist: %v\n", err)
				return 1
			}
			fmt.Fprintln(os.Stderr, "wrote "+name+" ("+strconv.Itoa(end-i)+" lines)")
		}
		return 0
	}
	body := strings.Join(lines, "\n")
	if len(lines) > 0 {
		body += "\n"
	}
	if *out == "" {
		fmt.Print(body)
		return 0
	}
	if err := os.WriteFile(*out, []byte(body), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "xcrack wordlist: %v\n", err)
		return 1
	}
	return 0
}
