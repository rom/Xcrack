package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rom/xcrypto/scheme/zipcrypto"
)

// runKP implements `xcrack kp`: ZipCrypto known-plaintext key recovery. Given
// aligned known plaintext and ciphertext it recovers the 96-bit internal key
// state (no password), optionally offloading the heavy search to a native
// bkcrack binary via --bkcrack. ZipCrypto is cryptographically broken by design,
// so this is legitimate cryptanalysis of a weak cipher, not an attack on a sound
// one.
func runKP(args []string) int {
	fs_ := flag.NewFlagSet("xcrack kp", flag.ContinueOnError)
	plainF := fs_.String("plain", "", "file of known plaintext bytes")
	cipherF := fs_.String("cipher", "", "ciphertext for those same bytes (equal length, same stream position)")
	bkcrackF := fs_.String("bkcrack", "", "offload the search to this bkcrack binary instead of the in-process attack")
	bkTimeout := fs_.Duration("bkcrack-timeout", 0, "wall-clock limit for the bkcrack run (0=none)")
	decryptF := fs_.String("decrypt", "", "after recovery, decrypt this ciphertext file (starting at the --plain stream position)")
	outF := fs_.String("out", "", "where --decrypt writes its plaintext (default: stdout)")
	fs_.Usage = func() {
		fmt.Fprint(os.Stderr, `xcrack kp -- ZipCrypto known-plaintext key recovery (Biham-Kocher)

Recovers the ZipCrypto internal key state from aligned known plaintext and
ciphertext -- no password needed. ZipCrypto is cryptographically broken by
design; recovering its running key state is legitimate cryptanalysis of a weak
cipher. Prints the recovered state as "key0 key1 key2" (hex), matching bkcrack.

USAGE:
  xcrack kp --plain P --cipher C [--bkcrack BIN] [--decrypt F --out G]

FLAGS:
  --plain FILE         known plaintext bytes
  --cipher FILE        ciphertext for the same bytes (equal length)
  --bkcrack BIN        offload to a native bkcrack binary (a constant factor
                       faster); the result is re-validated locally, so a faulty
                       or hostile engine can never cause a false positive
  --bkcrack-timeout D  wall-clock limit for the bkcrack run (e.g. 5m)
  --decrypt FILE       decrypt FILE (ciphertext starting at the same stream
                       position as --plain) with the recovered keys
  --out FILE           where --decrypt writes (default: stdout)

Needs at least 12 contiguous known-plaintext bytes; more recovers faster.
The in-process attack is compute-heavy -- prefer --bkcrack when available.
`)
	}
	if err := fs_.Parse(args); err != nil {
		return 2
	}
	if *plainF == "" || *cipherF == "" {
		fmt.Fprintln(os.Stderr, "xcrack kp: --plain and --cipher are required (see --help)")
		return 2
	}
	plain, err := os.ReadFile(*plainF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
		return 2
	}
	cipher, err := os.ReadFile(*cipherF)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
		return 2
	}
	if len(plain) != len(cipher) {
		fmt.Fprintf(os.Stderr, "xcrack kp: --plain (%d bytes) and --cipher (%d bytes) must be equal length\n", len(plain), len(cipher))
		return 2
	}
	if len(plain) < zipcrypto.MinKnownPlaintext {
		fmt.Fprintf(os.Stderr, "xcrack kp: need at least %d known-plaintext bytes, have %d\n", zipcrypto.MinKnownPlaintext, len(plain))
		return 2
	}

	var (
		keys  zipcrypto.Keys
		ok    bool
		rderr error
	)
	if *bkcrackF != "" {
		fmt.Fprintf(os.Stderr, "xcrack kp: offloading to %s\n", *bkcrackF)
		keys, ok, rderr = zipcrypto.RecoverKeysWith(plain, cipher, zipcrypto.ExternalBkcrack{Bin: *bkcrackF, Timeout: *bkTimeout})
	} else {
		fmt.Fprintln(os.Stderr, "xcrack kp: running in-process Biham-Kocher attack (compute-heavy; --bkcrack offloads it)")
		keys, ok = zipcrypto.RecoverKeys(plain, cipher)
	}
	if rderr != nil {
		fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", rderr)
		return 1
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "xcrack kp: keys not recovered")
		return 1
	}
	k0, k1, k2 := keys.Words()
	fmt.Printf("%08x %08x %08x\n", k0, k1, k2)

	if *decryptF != "" {
		ct, err := os.ReadFile(*decryptF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
			return 2
		}
		dec := keys // copy: Decrypt mutates the receiver
		dec.Decrypt(ct)
		if *outF == "" {
			_, _ = os.Stdout.Write(ct)
		} else if err := os.WriteFile(*outF, ct, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
			return 2
		}
	}
	return 0
}
