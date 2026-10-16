package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/rom/xcrack/pkg/xcrack"
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/hashline"
	"github.com/rom/xfileformats"
)

// runHashline emits crackable hash lines ($office$, $pdf$, ...) for external GPU
// crackers (hashcat / John the Ripper). It probes each file once and prints the
// hash string(s) to stdout; a human-readable "# <file> hashcat -m N" comment
// goes to stderr so stdout stays a clean hash file to pipe into a cracker.
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
		chs := challengesOf(reg, data)
		if len(chs) == 0 {
			fmt.Fprintf(os.Stderr, "# %s: no encrypted challenge found\n", path)
			exit = maxInt(exit, 1)
			continue
		}
		for _, cc := range chs {
			label := path
			if cc.entry != "" {
				label += ":" + cc.entry
			}
			r, ok := hashline.Emit(cc.ch)
			if !ok {
				fmt.Fprintf(os.Stderr, "# %s: no hash-line emitter for scheme %q yet\n", label, cc.ch.Scheme)
				exit = maxInt(exit, 1)
				continue
			}
			any = true
			mode := "n/a"
			if r.Hashcat >= 0 {
				mode = fmt.Sprintf("%d", r.Hashcat)
			}
			fmt.Fprintf(os.Stderr, "# %s  (hashcat -m %s  |  john --format=%s)\n", label, mode, r.John)
			fmt.Println(r.Line)
		}
	}
	if !any && exit == 0 {
		exit = 1
	}
	return exit
}

type chEntry struct {
	entry string
	ch    *xcrypto.Challenge
}

// challengesOf detects the format and collects the encryption challenge(s): one
// for a whole-file Encrypted format, or one per encrypted entry for a Container.
func challengesOf(reg *xfileformats.Registry, data []byte) []chEntry {
	peek := data
	if len(peek) > 512 {
		peek = peek[:512]
	}
	f, err := reg.Detect(peek)
	if err != nil {
		return nil
	}
	r := bytes.NewReader(data)
	size := int64(len(data))
	if enc, ok := f.(xfileformats.Encrypted); ok {
		ch, err := enc.Probe(r, size)
		if err != nil || ch == nil {
			return nil
		}
		return []chEntry{{"", ch}}
	}
	if c, ok := f.(xfileformats.Container); ok {
		entries, err := c.Entries(r, size)
		if err != nil {
			return nil
		}
		var out []chEntry
		for _, e := range entries {
			if e.Encrypted && e.Challenge != nil {
				out = append(out, chEntry{e.Path, e.Challenge})
			}
		}
		return out
	}
	return nil
}
