package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrypto/scheme/pdf"
)

// runThunderGen implements `xcrack thunder-gen`: build a precomputed
// time-memory-trade-off ("Thunder Table") that inverts the PDF V1/R2 user
// verifier /U = RC4(fileKey, pad) → 40-bit file key. Because that function has
// no per-file salt or ID, ONE table inverts every V1/R2 document, turning the
// 2^40 live sweep into a seconds-long `pdf-keyattack --table` lookup. Generation is
// the one-time cost; a full 2^40 table is a long job, so --dry-run prints the
// plan and a quick `--bits 24`-style partial table is good for a trial.
func runThunderGen(args []string) int {
	fs_ := flag.NewFlagSet("xcrack thunder-gen", flag.ContinueOnError)
	out := fs_.String("out", "", "output table file (required)")
	bits := fs_.Int("bits", 40, "key-space exponent to cover: 40 inverts every V1/R2 PDF; smaller builds a partial/trial table")
	length := fs_.Int("length", 4096, "chain length t: lookup costs ~tables×t²/2 image ops, so SMALL t => fast lookup but a larger table; the default balances a few-second lookup against table size (t=2^20 makes lookup as slow as the brute-force sweep)")
	chains := fs_.Int("chains", 1<<26, "chains per sub-table m: coverage rises with m×t×tables toward 2^bits, so larger t needs fewer chains (table size ≈ chains×tables×10 bytes)")
	tables := fs_.Int("tables", 4, "independent sub-tables (more => higher coverage)")
	workers := fs_.Int("workers", 0, "generation workers (0 = all cores)")
	gpu := fs_.Bool("gpu", false, "offload chain generation to an OpenCL device (needs a -tags opencl build with OpenCL hardware; falls back to CPU)")
	dryRun := fs_.Bool("dry-run", false, "print the generation plan (work, size, time estimate) and exit")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	if *out == "" && !*dryRun {
		fmt.Fprintln(os.Stderr, "xcrack thunder-gen: --out FILE is required")
		return 2
	}
	if *bits < 1 || *bits > 40 || *length < 1 || *chains < 1 || *tables < 1 {
		fmt.Fprintln(os.Stderr, "xcrack thunder-gen: --bits must be 1..40 and --length/--chains/--tables >= 1")
		return 2
	}

	// Plan: total chain work and an estimated wall-clock from a quick micro-bench
	// of the image function, plus the on-disk size (10 bytes per stored chain).
	totalChains := uint64(*tables) * uint64(*chains)
	totalOps := totalChains * uint64(*length)
	rate := pdf.BenchImageRate(250 * time.Millisecond) // images/sec, single core
	cores := *workers
	if cores <= 0 {
		cores = runtime.GOMAXPROCS(0)
	}
	est := time.Duration(0)
	if rate > 0 {
		// Clamp: seconds × 1e9 overflows int64 nanoseconds past ~9.2e9 s, which
		// would print a negative/garbage estimate for a very large plan. roundDur
		// renders the clamped max as ">1000 years".
		ns := float64(totalOps) / (rate * float64(cores)) * 1e9
		if ns >= float64(math.MaxInt64) {
			est = time.Duration(math.MaxInt64)
		} else {
			est = time.Duration(ns)
		}
	}
	fmt.Fprintf(os.Stderr, "thunder-gen plan: 2^%d key space, %d sub-tables × %d chains × %d columns\n", *bits, *tables, *chains, *length)
	fmt.Fprintf(os.Stderr, "  chain work   ~%s image ops   (≈ %s on %d core(s) at ~%.0fk/s/core)\n",
		humanCount(totalOps), roundDur(est), cores, rate/1e3)
	fmt.Fprintf(os.Stderr, "  table size   ~%s on disk (pre-dedup; merges shrink it)\n", humanBytes(totalChains*10))
	fmt.Fprintf(os.Stderr, "  coverage     rises with chains×columns×tables vs 2^%d; add --tables for ~100%%\n", *bits)
	if *dryRun {
		return 0
	}
	if *bits == 40 {
		fmt.Fprintln(os.Stderr, "  note: a full 2^40 table is a long one-time job — Ctrl-C is safe; try --bits 24 first, or --dry-run.")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// Optional GPU offload of the chain walk — the heavy part of generation. The
	// chain is byte-identical to the CPU walk, so the table is inverted by the same
	// CPU lookup; GenerateTable falls back to the CPU per sub-table if the device
	// errors, so a GPU hiccup never corrupts the table.
	var chain pdf.ChainComputer
	if *gpu {
		if acc, derr := accel.Detect(); derr != nil {
			fmt.Fprintf(os.Stderr, "xcrack thunder-gen: --gpu unavailable (%v); generating on CPU\n", derr)
		} else {
			defer acc.Close()
			if c := gpuChainComputer(acc); c != nil {
				chain = c
				for _, d := range acc.Devices() {
					fmt.Fprintf(os.Stderr, "  offloading chains to %s %s (%s)\n", d.Vendor, d.Name, d.Type)
				}
			} else {
				fmt.Fprintln(os.Stderr, "xcrack thunder-gen: --gpu device has no thunder-chain kernel; generating on CPU")
			}
		}
	}

	started := time.Now()
	tbl, err := pdf.GenerateTable(ctx, pdf.TableParams{
		KeyspaceBits: *bits, ChainLen: *length, Chains: *chains, Tables: *tables, Workers: *workers, Chain: chain,
	})
	if err != nil {
		if ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, "interrupted")
			return 130
		}
		fmt.Fprintf(os.Stderr, "xcrack thunder-gen: %v\n", err)
		return 2
	}

	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack thunder-gen: %v\n", err)
		return 2
	}
	bw := bufio.NewWriterSize(f, 1<<20)
	n, werr := tbl.WriteTo(bw)
	if werr == nil {
		werr = bw.Flush()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		fmt.Fprintf(os.Stderr, "xcrack thunder-gen: writing %s: %v\n", *out, werr)
		return 2
	}
	fmt.Printf("wrote %s: %s, %d chains over 2^%d, %d columns, %d sub-tables (%s)\n",
		*out, humanBytes(uint64(n)), tbl.Chains(), tbl.KeyspaceBits(), tbl.ChainLen(), *tables, roundDur(time.Since(started)))
	fmt.Println("use it with: xcrack pdf-keyattack --table " + *out + " FILE.pdf")
	return 0
}

// gpuChainComputer adapts an accelerator's PDFThunderChainer capability to the
// pdf.ChainComputer seam, or returns nil when the backend lacks it (so
// GenerateTable uses the CPU walk). The accelerator must outlive the returned
// closure (the caller keeps it open until generation finishes).
func gpuChainComputer(acc accel.Accelerator) pdf.ChainComputer {
	tc, ok := acc.(accel.PDFThunderChainer)
	if !ok {
		return nil
	}
	return func(n uint64, chainLen int, seed, startIdx, count uint64) ([]uint64, error) {
		return tc.PDFThunderChain(n, chainLen, seed, startIdx, count)
	}
}

func humanCount(n uint64) string {
	switch {
	case n >= 1e12:
		return fmt.Sprintf("%.1fT", float64(n)/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%.1fG", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.1fM", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.1fk", float64(n)/1e3)
	default:
		return fmt.Sprintf("%d", n)
	}
}

func humanBytes(n uint64) string {
	switch {
	case n >= 1<<40:
		return fmt.Sprintf("%.1f TiB", float64(n)/(1<<40))
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
