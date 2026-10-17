// Command candidate-pipeline shows how to build an advanced candidate stream in
// Go and feed it to the engine — the programmatic equivalent of the CLI's
// wordlist/rule/generator flags. It composes a base wordlist with case-toggling,
// a PRINCE chain, a Markov model trained on the same words, de-duplication, and
// optional sharding, then either cracks a target file with it or prints the
// stream (so you can see exactly what would be tried).
//
// Usage:
//
//	candidate-pipeline -words FILE [-shard I/N] [-stdout] [target]
//
// With a target it cracks; with -stdout it prints the candidates and exits.
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/candidates"
)

func main() {
	wordsPath := flag.String("words", "", "base wordlist file (one candidate per line)")
	shard := flag.String("shard", "", "only emit shard I/N of the keyspace, e.g. 0/4")
	toStdout := flag.Bool("stdout", false, "print the candidate stream instead of cracking")
	limit := flag.Int("limit", 0, "stop after this many candidates (0 = no cap)")
	flag.Parse()
	if *wordsPath == "" {
		fmt.Fprintln(os.Stderr, "usage: candidate-pipeline -words FILE [-shard I/N] [-stdout] [target]")
		os.Exit(2)
	}

	words, err := readLines(*wordsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read words: %v\n", err)
		os.Exit(1)
	}

	// build assembles a fresh, composed candidate stream. The engine (and the
	// -stdout preview) each need their own cursor, so this is a factory.
	build := func() xcrack.CandidateSource {
		base := candidates.Bytes(words...)

		// Case-toggle variants of each base word (hashcat "toggle" attack).
		toggled := candidates.ToggleCase(candidates.Bytes(words...), 4)

		// PRINCE: length-ordered concatenations of the base words.
		prince := candidates.Prince(candidates.Bytes(words...), 6, 16, 3, 200_000)

		// A Markov model trained on the base words, emitting likely strings first.
		model := candidates.TrainMarkov(words)
		markov := candidates.MarkovGen(model, 4, 12, 200_000)

		// Chain them in priority order, drop duplicates across the whole stream.
		stream := candidates.Dedup(candidates.Chain(base, toggled, prince, markov))

		// Optional sharding for distributed runs.
		if *shard != "" {
			i, n, err := parseShard(*shard)
			if err != nil {
				fmt.Fprintf(os.Stderr, "bad -shard: %v\n", err)
				os.Exit(2)
			}
			stream = candidates.Shard(stream, i, n)
		}
		return stream
	}

	if *toStdout {
		src := build()
		w := bufio.NewWriter(os.Stdout)
		defer w.Flush()
		for n := 0; ; n++ {
			if *limit > 0 && n >= *limit {
				break
			}
			c, err := src.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "stream: %v\n", err)
				os.Exit(1)
			}
			w.Write(c)
			w.WriteByte('\n')
		}
		return
	}

	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "no target given (use -stdout to preview the stream)")
		os.Exit(2)
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "read target: %v\n", err)
		os.Exit(1)
	}

	// Supply the composed stream through a CandidateProvider so the Pool uses it
	// on every Process call without threading a source through each call site.
	opts := xcrack.Options{
		Limits: func() xcrack.Limits {
			l := xcrack.DefaultLimits()
			l.MaxCandidates = int64(*limit)
			return l
		}(),
		CandidateProvider: xcrack.CandidateProviderFunc(func(context.Context) xcrack.CandidateSource {
			return build()
		}),
	}
	res, err := xcrack.Process(context.Background(), bytes.NewReader(data), int64(len(data)), nil, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "process: %v\n", err)
		os.Exit(1)
	}
	defer res.Close()
	if pws := res.Passwords(); len(pws) > 0 {
		fmt.Printf("recovered: %s\n", strings.Join(pws, ", "))
	} else {
		fmt.Println("no password found")
		os.Exit(1)
	}
}

func readLines(path string) ([][]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line != "" {
			out = append(out, []byte(line))
		}
	}
	return out, sc.Err()
}

func parseShard(spec string) (index, count int, err error) {
	parts := strings.SplitN(spec, "/", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("want I/N")
	}
	i, e1 := strconv.Atoi(parts[0])
	n, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || n < 1 || i < 0 || i >= n {
		return 0, 0, fmt.Errorf("want 0<=I<N, N>=1")
	}
	return i, n, nil
}
