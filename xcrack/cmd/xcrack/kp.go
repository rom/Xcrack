package main

import (
	"bytes"
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
	decryptF := fs_.String("decrypt", "", "after recovery, decrypt this full ZipCrypto entry (12-byte header + data)")
	offsetF := fs_.Int("offset", 0, "data offset (post-header) of --plain within the --decrypt entry (bkcrack -o)")
	keepHeaderF := fs_.Bool("keep-header", false, "keep the 12-byte encryption header in --decrypt output (default: drop it)")
	outF := fs_.String("out", "", "where --decrypt writes its plaintext (default: stdout)")
	fs_.Usage = func() {
		fmt.Fprint(os.Stderr, `xcrack kp -- ZipCrypto known-plaintext key recovery (Biham-Kocher)

Recovers the ZipCrypto internal key state from aligned known plaintext and
ciphertext -- no password needed. ZipCrypto is cryptographically broken by
design; recovering its running key state is legitimate cryptanalysis of a weak
cipher. Prints the recovered state as "key0 key1 key2" (hex), matching bkcrack.

USAGE:
  xcrack kp --plain P --cipher C [--bkcrack BIN]
           [--decrypt ENTRY --offset N [--keep-header] --out G]

FLAGS:
  --plain FILE         known plaintext bytes
  --cipher FILE        ciphertext for the same bytes (equal length)
  --bkcrack BIN        offload to a native bkcrack binary (a constant factor
                       faster); the result is re-validated locally, so a faulty
                       or hostile engine can never cause a false positive
  --bkcrack-timeout D  wall-clock limit for the bkcrack run (e.g. 5m)
  --decrypt ENTRY      decrypt a whole ZipCrypto entry (12-byte header + data):
                       the recovered state is rolled back over the header and any
                       earlier data to the entry start, so a mid-entry known
                       plaintext still decrypts the entire entry
  --offset N           data offset (post-header) of --plain within ENTRY (as in
                       bkcrack's -o; default 0 = known plaintext at data start)
  --keep-header        keep the 12-byte header in --decrypt output (default: drop)
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
		entry, err := os.ReadFile(*decryptF)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
			return 2
		}
		// plain[0] sits at absolute offset HeaderLen+offset within the entry (the
		// 12-byte ZipCrypto header precedes the data, like bkcrack's -o convention).
		abs := zipcrypto.HeaderLen + *offsetF
		if *offsetF < 0 || abs+len(cipher) > len(entry) {
			fmt.Fprintf(os.Stderr, "xcrack kp: --offset %d places the known plaintext outside the %d-byte entry\n", *offsetF, len(entry))
			return 2
		}
		if !bytes.Equal(entry[abs:abs+len(cipher)], cipher) {
			fmt.Fprintln(os.Stderr, "xcrack kp: --cipher does not match the entry at --offset (wrong --offset or mismatched files)")
			return 2
		}
		// Roll the recovered state (before plain[0]) back over the preceding
		// ciphertext (header + any earlier data) to the entry start, then decrypt
		// the whole entry forward.
		start, _ := keys.RollBack(entry[:abs])
		full := append([]byte(nil), entry...)
		start.Decrypt(full)
		out := full
		if !*keepHeaderF {
			out = full[zipcrypto.HeaderLen:] // abs >= HeaderLen, so this is safe
		}
		if *outF == "" {
			_, _ = os.Stdout.Write(out)
		} else if err := os.WriteFile(*outF, out, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
			return 2
		}
	}
	return 0
}
