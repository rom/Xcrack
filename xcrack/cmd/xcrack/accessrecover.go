package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rom/xfileformats/formats/access"
)

// runAccessRecover implements `xcrack access-recover FILE`: recover a Microsoft
// Access (Jet .mdb) database password directly from the header, with no
// cracking. Jet3/Jet4 store the password XOR-obfuscated with fixed, public
// material, so it is simply decoded (access.RecoverJetPassword). ACE (.accdb,
// Access 2007+) uses a real Office-style KDF with no such shortcut and is
// reported as needing a password search instead.
func runAccessRecover(args []string) int {
	fs_ := flag.NewFlagSet("xcrack access-recover", flag.ContinueOnError)
	var sources stringSlice
	fs_.Var(&sources, "source", "source file (repeatable)")
	fs_.Var(&sources, "s", "alias for --source")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) != 1 {
		fmt.Fprintln(os.Stderr, "xcrack access-recover: expects exactly one file")
		return 2
	}
	// The password lives in the first header page; a bounded read is plenty and
	// avoids slurping a large database.
	f, err := os.Open(srcArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.Read(head)
	head = head[:n]

	variant := access.Variant(head)
	switch variant {
	case "ace":
		fmt.Fprintln(os.Stderr, "xcrack access-recover: this is an ACE (.accdb, Access 2007+) database.")
		fmt.Fprintln(os.Stderr, "  ACE uses a real Office-style KDF — run a password search instead.")
		return 1
	case "jet3", "jet4":
		// fall through
	default:
		fmt.Fprintln(os.Stderr, "xcrack access-recover: not a Microsoft Access (Jet) database.")
		return 1
	}

	res, ok := access.RecoverJetPassword(head)
	if !ok {
		fmt.Fprintln(os.Stderr, "xcrack access-recover: could not read the Jet header (truncated?).")
		return 1
	}
	if !res.HasPassword {
		fmt.Printf("%s database has no database password set\n", res.Variant)
		return 0
	}
	fmt.Printf("recovered %s database password: %s\n", res.Variant, res.Password)
	return 0
}
