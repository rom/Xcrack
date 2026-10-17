package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	xvba "github.com/rom/xcrypto/scheme/vbaproject"
	"github.com/rom/xfileformats/formats/vbaproject"
)

// runVBARecover implements `xcrack vba-recover FILE`: recover a Microsoft VBA
// project-protection password from a legacy .doc/.xls/.ppt (OLE2/CFB), a
// macro-enabled OOXML .docm/.xlsm/.pptm (its vbaProject.bin is unwrapped), or a
// standalone vbaProject.bin. Per MS-OVBA the password is in the PROJECT stream's
// DPB field. If it is stored in the clear it is printed directly (no cracking);
// if it is a salted SHA-1 hash, the John/hashcat hash lines are emitted so the
// password can be cracked (SHA1(password||salt): John dynamic_24, hashcat -m 110
// --hex-salt). Run `xcrack --as vbaproject -w LIST FILE` to crack it in-engine.
func runVBARecover(args []string) int {
	fs_ := flag.NewFlagSet("xcrack vba-recover", flag.ContinueOnError)
	var sources stringSlice
	fs_.Var(&sources, "source", "source file (repeatable)")
	fs_.Var(&sources, "s", "alias for --source")
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	srcArgs := append([]string(sources), fs_.Args()...)
	if len(srcArgs) != 1 {
		fmt.Fprintln(os.Stderr, "xcrack vba-recover: expects exactly one file")
		return 2
	}
	data, err := os.ReadFile(srcArgs[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack: %v\n", err)
		return 2
	}

	res, err := vbaproject.ParseProject(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, "xcrack vba-recover: no VBA project password found (not a VBA carrier, or no DPB field).")
		return 1
	}
	switch res.Kind {
	case xvba.KindNone:
		fmt.Println("VBA project has no protection password set")
		return 0
	case xvba.KindPlaintext:
		fmt.Printf("recovered VBA project password: %s\n", res.Plaintext)
		return 0
	case xvba.KindHash:
		hashHex := hex.EncodeToString(res.Hash)
		saltHex := hex.EncodeToString(res.Key)
		fmt.Println("VBA project password is stored as a salted SHA-1 hash — crack it:")
		fmt.Printf("  hashcat (-m 110 --hex-salt): %s:%s\n", hashHex, saltHex)
		fmt.Printf("  john (dynamic_24):           $dynamic_24$%s$HEX$%s\n", hashHex, saltHex)
		fmt.Printf("  in-engine:                   xcrack --as vbaproject -w LIST %s\n", srcArgs[0])
		return 0
	default:
		fmt.Fprintln(os.Stderr, "xcrack vba-recover: unrecognized VBA password structure.")
		return 1
	}
}
