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

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/officebinary"
	"github.com/rom/xfileformats"
)

// runOfficeKeyAttack implements `xcrack office-keyattack FILE`: the Elcomsoft
// "Thunder Tables"-style direct 40-bit key attack on Office 97/2000 RC4 files
// (.doc/.xls/.ppt). Instead of guessing the password, it sweeps the 2^40 trunc
// keyspace against the document verifier and recovers the key — defeating even a
// long, random password. The sweep is shardable (--shard) for distribution and
// parallel across CPU cores (--workers). Office XP/2003 "CryptoAPI" RC4 is NOT
// attackable this way (its 160-bit SHA-1 intermediate leaves no 40-bit
// bottleneck), and the command says so rather than running a futile sweep.
func runOfficeKeyAttack(args []string) int {
	fs_ := flag.NewFlagSet("xcrack office-keyattack", flag.ContinueOnError)
	var sources stringSlice
	fs_.Var(&sources, "source", "source file (repeatable)")
	fs_.Var(&sources, "s", "alias for --source")
	workers := fs_.Int("workers", 0, "parallel CPU workers (0 = all cores)")
	shard := fs_.String("shard", "", "sweep only shard i/N of the keyspace (e.g. 0/8) for distribution")
	start := fs_.Uint64("start", 0, "first keyspace index to scan (resume)")
	maxN := fs_.Uint64("max", 0, "scan at most this many keys this run (0 = to end of range)")
	quiet := fs_.Bool("quiet", false, "suppress progress output")
	fs_.BoolVar(quiet, "q", false, "alias for --quiet")
	gpu := fs_.Bool("gpu", false, "offload the 2^40 sweep to an OpenCL device (needs a -tags opencl build with OpenCL hardware; falls back to CPU)")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) != 1 {
		fmt.Fprintln(os.Stderr, "xcrack office-keyattack: expects exactly one file")
		return 2
	}
	data, err := os.ReadFile(srcArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	ch := findMSORC4(xcrack.DefaultRegistry(), data)
	if ch == nil {
		fmt.Fprintln(os.Stderr, "xcrack office-keyattack: no Office 97/2000 RC4 encryption found.")
		fmt.Fprintln(os.Stderr, "  (Office XP/2003 'CryptoAPI' RC4 and OOXML are not 40-bit key-attackable;")
		fmt.Fprintln(os.Stderr, "   run a password search on those instead.)")
		return 1
	}

	lo, hi, serr := resolveRange(*shard, *start, *maxN, officebinary.MaxRC4Trunc)
	if serr != nil {
		fmt.Fprintf(os.Stderr, "xcrack office-keyattack: %v\n", serr)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	trunc, found, aerr := sweepKeyspace(ctx, ch, lo, hi, *workers, !*quiet, *gpu)
	if aerr != nil && aerr != context.Canceled {
		fmt.Fprintf(os.Stderr, "xcrack office-keyattack: %v\n", aerr)
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
	fmt.Printf("recovered 40-bit RC4 key (trunc): %s\n", hex.EncodeToString(trunc))
	fmt.Println("the document is unlocked by this key regardless of the original password")
	return 0
}

// findMSORC4 probes data for an Office 97/2000 RC4 ("mso-rc4") challenge.
func findMSORC4(reg *xfileformats.Registry, data []byte) *xcrypto.Challenge {
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
		if ch.Scheme == "mso-rc4" {
			return ch
		}
		return nil // recognized as some other (non-attackable) Office scheme
	}
	return nil
}

// resolveRange turns the --shard / --start / --max flags into a [lo, hi) index
// window over a keyspace of size max (shared by the Office trunc sweep and the
// PDF file-key sweep, both 2^40).
func resolveRange(shard string, start, maxN, max uint64) (lo, hi uint64, err error) {
	lo, hi = 0, max
	if shard != "" {
		var i, n uint64
		if _, e := fmt.Sscanf(shard, "%d/%d", &i, &n); e != nil || n == 0 || i >= n {
			return 0, 0, fmt.Errorf("--shard: want i/N with 0<=i<N, got %q", shard)
		}
		per := max / n
		lo = per * i
		hi = lo + per
		if i == n-1 {
			hi = max // last shard mops up the remainder
		}
	}
	if start > lo {
		lo = start
	}
	if maxN > 0 && lo+maxN < hi {
		hi = lo + maxN
	}
	if lo >= hi {
		return 0, 0, fmt.Errorf("empty range [%d, %d)", lo, hi)
	}
	return lo, hi, nil
}

// sweepKeyspace runs the attack over [lo, hi), chunking so it can report
// progress and react to interruption between chunks. With useGPU it offloads the
// per-chunk sweep to an OpenCL device (OldOfficeKeySearcher), re-checking any hit
// on the CPU; it falls back to the CPU sweep when no device is built/available.
func sweepKeyspace(ctx context.Context, ch *xcrypto.Challenge, lo, hi uint64, workers int, progress, useGPU bool) ([]byte, bool, error) {
	salt := ch.KDF.Salt
	encVerifier := ch.Extra["enc_verifier"]
	encVerifierHash := ch.Verifier

	var ks accel.OldOfficeKeySearcher
	if useGPU {
		acc, err := accel.Detect()
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack office-keyattack: --gpu unavailable (%v); using CPU\n", err)
		} else {
			defer acc.Close()
			if k, ok := acc.(accel.OldOfficeKeySearcher); ok {
				ks = k
				if progress {
					for _, d := range acc.Devices() {
						fmt.Fprintf(os.Stderr, "offloading to %s %s (%s)\n", d.Vendor, d.Name, d.Type)
					}
				}
			} else {
				fmt.Fprintln(os.Stderr, "xcrack office-keyattack: --gpu device has no key-search kernel; using CPU")
			}
		}
	}

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
		var (
			trunc []byte
			found bool
			err   error
		)
		if ks != nil {
			trunc, found, err = ks.OldOfficeKeySearch(salt, encVerifier, encVerifierHash, base, n)
			// Authoritative CPU re-check: the device never decides correctness.
			if found {
				if ok, _ := officebinary.VerifyRC4Trunc(trunc, salt, encVerifier, encVerifierHash); !ok {
					trunc, found = nil, false
				}
			}
		} else {
			trunc, found, err = officebinary.RC4KeyAttackParallel(ctx, salt, encVerifier, encVerifierHash, base, n, workers)
		}
		if err != nil {
			return nil, false, err
		}
		if found {
			return trunc, true, nil
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
