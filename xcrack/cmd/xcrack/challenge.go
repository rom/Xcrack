package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto"
	"github.com/rom/xfileformats"
)

// runExportChallenge implements `xcrack export-challenge`: it probes each source
// once and emits the portable JSON challenge envelope(s) a separate engine (a
// GPU box, a hashcat/John bridge, or another xcrack instance) can crack offline.
// The recovered password is brought back with `xcrack --resume-from` (see
// loadRecoveredPasswords). This surfaces xcrypto's challenge export/import —
// previously a library-only capability — on the command line.
func runExportChallenge(args []string) int {
	fs_ := flag.NewFlagSet("xcrack export-challenge", flag.ContinueOnError)
	var sources stringSlice
	fs_.Var(&sources, "source", "source file (repeatable)")
	fs_.Var(&sources, "s", "alias for --source")
	asF := fs_.String("as", "", "force a scheme for a magic-less file (e.g. sqlcipher)")
	outF := fs_.String("out", "", "write the envelopes here (default: stdout)")
	fs_.StringVar(outF, "o", "", "alias for --out")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) == 0 {
		fmt.Fprintln(os.Stderr, "xcrack export-challenge: no sources (give files or --source)")
		return 2
	}
	files, err := expandSources(srcArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	reg := xcrack.DefaultRegistry()
	if *asF != "" {
		r, ok := xcrack.ForceRegistry(*asF)
		if !ok {
			fmt.Fprintf(os.Stderr, "xcrack export-challenge: --as: unknown force-format %q (supported: sqlcipher)\n", *asF)
			return 2
		}
		reg = r
	}

	var envs []*xcrypto.ExportedChallenge
	for _, path := range files {
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %s: %v\n", path, rerr)
			continue
		}
		envs = append(envs, challengesFor(reg, path, data)...)
	}
	if len(envs) == 0 {
		fmt.Fprintln(os.Stderr, "xcrack export-challenge: no exportable challenges found (unencrypted or unsupported)")
		return 1
	}

	out := os.Stdout
	if *outF != "" {
		f, cerr := os.Create(*outF)
		if cerr != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %v\n", cerr)
			return 2
		}
		defer f.Close()
		out = f
	}
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(envs); err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	return 0
}

// challengesFor probes one file for its top-level crackable challenge(s): a
// whole-file encrypted format yields one envelope; a container yields one per
// encrypted entry. It does not recurse into content that is itself encrypted
// (that needs the password). Parsing runs under a recover guard so a malformed
// file yields no envelope rather than a panic.
func challengesFor(reg *xfileformats.Registry, path string, data []byte) (out []*xcrypto.ExportedChallenge) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "xcrack: %s: skipped (malformed): %v\n", path, r)
		}
	}()
	r := bytes.NewReader(data)
	size := int64(len(data))
	for _, cand := range reg.DetectAll(peekBytes(data)) {
		caps := cand.Caps()
		if enc, ok := cand.(xfileformats.Encrypted); ok && caps.Encrypted {
			ch, perr := enc.Probe(r, size)
			if perr != nil || ch == nil {
				continue // recognizes the magic but not this file (or plaintext)
			}
			out = append(out, xcrypto.ExportChallenge(ch, path))
			return out
		}
		if cont, ok := cand.(xfileformats.Container); ok && caps.Container {
			entries, eerr := cont.Entries(r, size)
			if eerr != nil {
				continue
			}
			for _, e := range entries {
				if e != nil && e.Encrypted && e.Challenge != nil {
					out = append(out, xcrypto.ExportChallenge(e.Challenge, path+"!/"+e.Path))
				}
			}
			return out
		}
	}
	return out
}

// peekBytes returns the detection peek window (mirrors the engine's bound).
func peekBytes(data []byte) []byte {
	if len(data) > xfileformats.PeekSize {
		return data[:xfileformats.PeekSize]
	}
	return data
}

// loadRecoveredPasswords reads one or more RecoveredPassword envelopes (as
// emitted by an external cracker after solving an exported challenge) and
// returns the passwords, so `xcrack --resume-from` can resume decryption with
// them tried first. A file may contain a single envelope or a JSON array.
func loadRecoveredPasswords(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		// Accept either a single object or an array of them.
		trimmed := bytes.TrimSpace(data)
		var items [][]byte
		if len(trimmed) > 0 && trimmed[0] == '[' {
			var raw []json.RawMessage
			if err := json.Unmarshal(trimmed, &raw); err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			for _, m := range raw {
				items = append(items, m)
			}
		} else {
			items = append(items, trimmed)
		}
		for _, m := range items {
			rp, err := xcrypto.UnmarshalRecoveredPassword(m)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			if rp.Password != "" {
				out = append(out, rp.Password)
			}
		}
	}
	return out, nil
}
