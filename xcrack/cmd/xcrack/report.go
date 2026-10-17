package main

import (
	"fmt"
	"os"

	"github.com/rom/xfileformats"
)

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
