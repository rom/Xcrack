package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto/hashline"
	"github.com/rom/xfileformats"
)

// runHashline emits crackable hash lines ($office$, $pdf$, $zip2$, ...) for
// external GPU crackers (hashcat / John the Ripper). It probes each file once
// and prints the hash string(s) to stdout; a human-readable
// "# <file> hashcat -m N" comment goes to stderr so stdout stays a clean hash
// file to pipe into a cracker.
func runHashline(args []string) int {
	fs_ := flag.NewFlagSet("xcrack hashline", flag.ContinueOnError)
	var sources stringSlice
	fs_.Var(&sources, "source", "source file (repeatable)")
	fs_.Var(&sources, "s", "alias for --source")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) == 0 {
		fmt.Fprintln(os.Stderr, "xcrack hashline: no sources (give files or --source)")
		return 2
	}
	files, err := expandSources(srcArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	reg := xcrack.DefaultRegistry()
	exit, any := 0, false
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
			exit = maxInt(exit, 2)
			continue
		}
		lines := linesOf(reg, data)
		if len(lines) == 0 {
			fmt.Fprintf(os.Stderr, "# %s: no hash-line emitter matched (unencrypted, unknown, or CPU-only scheme)\n", path)
			exit = maxInt(exit, 1)
			continue
		}
		for _, l := range lines {
			label := path
			if l.Target != "" {
				label += ":" + l.Target
			}
			any = true
			mode := "n/a"
			if l.Hashcat >= 0 {
				mode = fmt.Sprintf("%d", l.Hashcat)
			}
			fmt.Fprintf(os.Stderr, "# %s  (hashcat -m %s  |  john --format=%s)\n", label, mode, l.John)
			fmt.Println(l.Line)
		}
	}
	if !any && exit == 0 {
		exit = 1
	}
	return exit
}

// linesOf detects the format and collects crackable hash lines for it. It walks
// every format that claims the stream (not just the single best match, so an
// AES ZIP is not shadowed by another format that shares the PK magic) and
// returns the first non-empty result. A format implementing
// hashline.LineExporter is preferred — it reads the full ciphertext a GPU
// cracker needs (e.g. WinZip AES $zip2$); otherwise lines are derived from the
// lightweight probe-time Challenge via hashline.Emit, one for a whole-file
// Encrypted format or one per encrypted entry for a Container.
func linesOf(reg *xfileformats.Registry, data []byte) []hashline.Labeled {
	peek := data
	if len(peek) > 512 {
		peek = peek[:512]
	}
	r := bytes.NewReader(data)
	size := int64(len(data))
	for _, f := range reg.DetectAll(peek) {
		// Prefer a direct line exporter (full ciphertext + auth, e.g. $zip2$).
		if le, ok := f.(hashline.LineExporter); ok {
			if ls, err := le.HashcatLines(r, size); err == nil && len(ls) > 0 {
				return ls
			}
		}
		if enc, ok := f.(xfileformats.Encrypted); ok {
			ch, err := enc.Probe(r, size)
			if err != nil || ch == nil {
				continue
			}
			if res, ok := hashline.Emit(ch); ok {
				return []hashline.Labeled{{Result: res}}
			}
			continue
		}
		if c, ok := f.(xfileformats.Container); ok {
			entries, err := c.Entries(r, size)
			if err != nil {
				continue
			}
			var out []hashline.Labeled
			for _, e := range entries {
				if e.Encrypted && e.Challenge != nil {
					if res, ok := hashline.Emit(e.Challenge); ok {
						out = append(out, hashline.Labeled{Target: e.Path, Result: res})
					}
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return nil
}
