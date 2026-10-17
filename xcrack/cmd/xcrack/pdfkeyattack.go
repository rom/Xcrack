package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/scheme/pdf"
	"github.com/rom/xfileformats"
)

// runPDFKeyAttack implements `xcrack pdf-keyattack FILE`: the direct 40-bit key
// attack on the PDF Standard Security Handler's RC4 scheme (V1/R2, and any
// R3/R4 document whose file key is 40 bits). The PDF file key is derived by a
// single MD5 truncated to 5 bytes, independent of the password's length, so
// instead of guessing the password it sweeps the 2^40 file-key space against
// the /U verifier and recovers the key — defeating even a long, random
// password. The sweep is shardable (--shard) for distribution and parallel
// across CPU cores (--workers). 128-bit RC4 and the AESV2/AESV3 schemes are NOT
// attackable this way, and the command says so rather than running a futile
// sweep.
func runPDFKeyAttack(args []string) int {
	fs_ := flag.NewFlagSet("xcrack pdf-keyattack", flag.ContinueOnError)
	var sources stringSlice
	fs_.Var(&sources, "source", "source file (repeatable)")
	fs_.Var(&sources, "s", "alias for --source")
	workers := fs_.Int("workers", 0, "parallel CPU workers (0 = all cores)")
	shard := fs_.String("shard", "", "sweep only shard i/N of the keyspace (e.g. 0/8) for distribution")
	start := fs_.Uint64("start", 0, "first keyspace index to scan (resume)")
	maxN := fs_.Uint64("max", 0, "scan at most this many keys this run (0 = to end of range)")
	quiet := fs_.Bool("quiet", false, "suppress progress output")
	fs_.BoolVar(quiet, "q", false, "alias for --quiet")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) != 1 {
		fmt.Fprintln(os.Stderr, "xcrack pdf-keyattack: expects exactly one file")
		return 2
	}
	data, err := os.ReadFile(srcArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	h := findPDFRC4(xcrack.DefaultRegistry(), data)
	if h == nil {
		fmt.Fprintln(os.Stderr, "xcrack pdf-keyattack: no 40-bit RC4 PDF encryption found.")
		fmt.Fprintln(os.Stderr, "  (128-bit RC4 and the AES PDF schemes are not 40-bit key-attackable;")
		fmt.Fprintln(os.Stderr, "   run a password search on those instead.)")
		return 1
	}

	lo, hi, serr := resolveRange(*shard, *start, *maxN, pdf.MaxRC4FileKey)
	if serr != nil {
		fmt.Fprintf(os.Stderr, "xcrack pdf-keyattack: %v\n", serr)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	key, found, aerr := sweepPDFKeyspace(ctx, h, lo, hi, *workers, !*quiet)
	if aerr != nil && aerr != context.Canceled {
		fmt.Fprintf(os.Stderr, "xcrack pdf-keyattack: %v\n", aerr)
		return 2
	}
	if !found {
		if ctx.Err() != nil {
			fmt.Fprintf(os.Stderr, "interrupted; resume with --start %d\n", lo)
			return 130
		}
		fmt.Fprintf(os.Stderr, "key not found in range [%d, %d)\n", lo, hi)
		return 1
	}
	fmt.Printf("recovered 40-bit PDF file key: %s\n", hex.EncodeToString(key))
	fmt.Println("every string and stream decrypts with this key regardless of the original password")
	return 0
}

// findPDFRC4 probes data for a 40-bit RC4 PDF and returns the parsed handler if
// it is key-attackable; nil for a stronger (or non-PDF) scheme.
func findPDFRC4(reg *xfileformats.Registry, data []byte) *pdf.Handler {
	r := bytes.NewReader(data)
	size := int64(len(data))
	defer func() { _ = recover() }()
	for _, cand := range reg.DetectAll(peekBytes(data)) {
		enc, ok := cand.(xfileformats.Encrypted)
		if !ok || !cand.Caps().Encrypted {
			continue
		}
		ch, perr := enc.Probe(r, size)
		if perr != nil || ch == nil {
			continue
		}
		if ch.Scheme != "pdf-rc4" {
			return nil // recognized as some other (non-attackable) scheme
		}
		h, herr := pdf.Unmarshal(ch.Extra)
		if herr != nil || !h.RC4KeyAttackable() {
			return nil
		}
		return h
	}
	return nil
}

// sweepPDFKeyspace runs the attack over [lo, hi), chunking so it can report
// progress and react to interruption between chunks.
func sweepPDFKeyspace(ctx context.Context, h *pdf.Handler, lo, hi uint64, workers int, progress bool) ([]byte, bool, error) {
	const chunk = uint64(1) << 28 // ~268M keys per progress step
	started := time.Now()
	for base := lo; base < hi; base += chunk {
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		n := chunk
		if base+n > hi {
			n = hi - base
		}
		key, found, err := h.RC4KeyAttackParallel(ctx, base, n, workers)
		if err != nil {
			return nil, false, err
		}
		if found {
			return key, true, nil
		}
		if progress {
			done := base + n - lo
			total := hi - lo
			rate := float64(done) / time.Since(started).Seconds()
			fmt.Fprintf(os.Stderr, "\rscanned %d/%d (%.1f%%) ~%.0fM keys/s",
				done, total, 100*float64(done)/float64(total), rate/1e6)
		}
	}
	if progress {
		fmt.Fprintln(os.Stderr)
	}
	return nil, false, nil
}
