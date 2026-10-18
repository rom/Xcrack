package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
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
	gpuBatch := fs_.Int("gpu-batch", 0, "chains per GPU submission with --gpu (0 = auto, sized to stay under the device's compute watchdog); lower it if a run hits a GPU 'ring timeout'/'context lost' (also via XCRACK_GPU_CHAIN_BATCH)")
	progressF := fs_.String("progress", "", "periodic progress to stderr: 'N%' every N percent (N=1,5,10,25), or 'N<hour|day>' every N hours/days (e.g. 5%, 2hour, 1day)")
	dryRun := fs_.Bool("dry-run", false, "print the generation plan (work, size, time estimate) and exit")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	prog, perr := parseThunderProgress(*progressF)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "xcrack thunder-gen: --progress: %v\n", perr)
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
	// Resolve the per-submission GPU batch: the flag wins, else XCRACK_GPU_CHAIN_BATCH,
	// else 0 (GenerateTable sizes it automatically from --length).
	gpuBatchN := *gpuBatch
	if gpuBatchN == 0 {
		if v := os.Getenv("XCRACK_GPU_CHAIN_BATCH"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				gpuBatchN = n
			}
		}
	}

	var chain pdf.ChainComputer
	if *gpu {
		if acc, derr := accel.Detect(); derr != nil {
			fmt.Fprintf(os.Stderr, "xcrack thunder-gen: --gpu unavailable (%v); generating on CPU\n", derr)
		} else {
			defer acc.Close()
			switch c := gpuChainComputer(acc); {
			case c == nil:
				fmt.Fprintln(os.Stderr, "xcrack thunder-gen: --gpu device has no thunder-chain kernel; generating on CPU")
			default:
				// Prove the device's kernels — including the thunder-chain generator —
				// match the CPU reference before trusting the device for the whole
				// table. Unlike the live crack loop, a wrong endpoint here is not
				// re-checked anywhere, so a miscomputing kernel would silently produce a
				// corrupt table; on any mismatch we generate on the CPU instead.
				if err := accel.GPUSelfTestWith(acc); err != nil {
					fmt.Fprintf(os.Stderr, "xcrack thunder-gen: --gpu self-test failed (%v); generating on CPU\n", err)
				} else {
					chain = c
					for _, d := range acc.Devices() {
						fmt.Fprintf(os.Stderr, "  offloading chains to %s %s (%s)\n", d.Vendor, d.Name, d.Type)
					}
					if gpuBatchN > 0 {
						fmt.Fprintf(os.Stderr, "  GPU submission batch: %d chains/call (--gpu-batch)\n", gpuBatchN)
					} else {
						fmt.Fprintln(os.Stderr, "  GPU submission batch: auto (lower --gpu-batch if you hit a 'ring timeout'/'context lost')")
					}
				}
			}
		}
	}

	started := time.Now()
	params := pdf.TableParams{
		KeyspaceBits: *bits, ChainLen: *length, Chains: *chains, Tables: *tables, Workers: *workers, Chain: chain, GPUChainBatch: gpuBatchN,
	}
	if prog != nil {
		prog.start = started
		prog.lastTime = started
		params.Progress = prog.report
	}
	tbl, err := pdf.GenerateTable(ctx, params)
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

// thunderProgress renders thunder-gen progress on a schedule: either every
// `pct` percent of chains generated, or every `interval` of wall-clock. Its
// report method is the pdf.TableParams.Progress callback (called from one
// goroutine, so its mutable state needs no locking).
type thunderProgress struct {
	pct      int           // percent step (1,5,10,25); 0 => time-based
	interval time.Duration // time step; 0 => percent-based
	start    time.Time
	lastTime time.Time
	lastPct  int       // last percent milestone printed (percent mode)
	finished bool      // 100% already printed
	out      io.Writer // nil => os.Stderr (overridable for tests)
	now      func() time.Time
}

func (p *thunderProgress) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// parseThunderProgress parses the --progress spec. "" disables progress.
// "N%" (N in 1,5,10,25) is percent-stepped; "N<hour|day>" (N>=1) is
// time-stepped. Any other form is an error.
func parseThunderProgress(spec string) (*thunderProgress, error) {
	spec = strings.TrimSpace(strings.ToLower(spec))
	if spec == "" {
		return nil, nil
	}
	if strings.HasSuffix(spec, "%") {
		n, err := strconv.Atoi(strings.TrimSpace(strings.TrimSuffix(spec, "%")))
		if err != nil {
			return nil, fmt.Errorf("want a number before %% (e.g. 5%%), got %q", spec)
		}
		switch n {
		case 1, 5, 10, 25:
			return &thunderProgress{pct: n}, nil
		default:
			return nil, fmt.Errorf("percent step must be 1, 5, 10 or 25, got %d", n)
		}
	}
	// Time form: split the leading digits from a trailing hour/day unit.
	i := 0
	for i < len(spec) && spec[i] >= '0' && spec[i] <= '9' {
		i++
	}
	if i == 0 {
		return nil, fmt.Errorf("want 'N%%' or 'N<hour|day>' (e.g. 10%%, 2hour, 1day), got %q", spec)
	}
	n, err := strconv.Atoi(spec[:i])
	if err != nil || n < 1 {
		return nil, fmt.Errorf("the count must be a positive integer, got %q", spec)
	}
	var unit time.Duration
	switch strings.TrimSpace(spec[i:]) {
	case "h", "hour", "hours":
		unit = time.Hour
	case "d", "day", "days":
		unit = 24 * time.Hour
	default:
		return nil, fmt.Errorf("the time unit must be hour or day (e.g. 2hour, 1day), got %q", spec)
	}
	return &thunderProgress{interval: unit * time.Duration(n)}, nil
}

// report is the pdf progress callback: it surfaces a line when the configured
// percent milestone or time interval is reached (and always a final 100%).
func (p *thunderProgress) report(done, total uint64) {
	if total == 0 {
		return
	}
	pct := int(done * 100 / total)
	now := p.clock()
	switch {
	case done >= total:
		if p.finished {
			return
		}
		p.finished = true
	case p.pct > 0:
		milestone := (pct / p.pct) * p.pct
		if milestone <= p.lastPct || milestone == 0 {
			return
		}
		p.lastPct = milestone
		pct = milestone
	default: // time-based
		if now.Sub(p.lastTime) < p.interval {
			return
		}
		p.lastTime = now
	}
	elapsed := now.Sub(p.start)
	eta := "?"
	if done > 0 && done < total {
		eta = roundDur(time.Duration(float64(elapsed) * float64(total-done) / float64(done)))
	}
	w := p.out
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, "thunder-gen progress: %d%% (%s/%s chains, elapsed %s, eta %s)\n",
		pct, humanCount(done), humanCount(total), elapsed.Round(time.Second), eta)
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
