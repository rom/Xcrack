package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rom/xcrypto/scheme/zipcrypto"
	"github.com/rom/xfileformats/formats/zip"
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
	recoverPwF := fs_.String("recover-password", "", "recover the password via bkcrack as MAXLEN:CHARSET, e.g. 8:?l?d (requires --bkcrack and --decrypt)")
	outF := fs_.String("out", "", "where --decrypt writes its plaintext (default: stdout)")
	zipF := fs_.String("zip", "", "after recovery, decrypt EVERY ZipCrypto entry of this archive with the shared key state (cross-entry reuse; requires --decrypt to establish the entry-start state)")
	zipOutF := fs_.String("zip-out", "", "directory to write the --zip decrypted entries into (default: just list them)")
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
  --recover-password MAXLEN:CHARSET
                       after rolling back to the entry start, recover the actual
                       password via bkcrack (e.g. 8:?l?d). Requires --bkcrack and
                       --decrypt. The result is re-validated locally.
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
	if *recoverPwF != "" && (*decryptF == "" || *bkcrackF == "") {
		fmt.Fprintln(os.Stderr, "xcrack kp: --recover-password requires --bkcrack and --decrypt (the entry start is needed)")
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
		keys, ok, rderr = zipcrypto.RecoverKeysWith(context.Background(), plain, cipher, zipcrypto.ExternalBkcrack{Bin: *bkcrackF, Timeout: *bkTimeout})
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

	var (
		entryStart zipcrypto.Keys
		haveStart  bool
	)
	if *zipF != "" && *decryptF == "" {
		fmt.Fprintln(os.Stderr, "xcrack kp: --zip requires --decrypt (the known-plaintext entry) to establish the archive-wide key state")
		return 2
	}
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
		entryStart = start // state before the entry = NewKeys(password); copy before Decrypt mutates start
		haveStart = true
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
		if *recoverPwF != "" {
			if code := recoverPassword(entryStart, *recoverPwF, *bkcrackF, *bkTimeout); code != 0 {
				return code
			}
		}
	}

	if *zipF != "" {
		if !haveStart {
			fmt.Fprintln(os.Stderr, "xcrack kp: --zip: could not establish the entry-start key state")
			return 2
		}
		if code := decryptArchive(*zipF, entryStart, *zipOutF); code != 0 {
			return code
		}
	}
	return 0
}

// decryptArchive decrypts every traditional-ZipCrypto entry of the archive with
// the shared entry-start key state (cross-entry key reuse): after one
// known-plaintext recovery, the rest of the archive opens with no further
// search. Each entry is CRC-checked, so a wrong state recovers nothing. If
// outDir is set, each recovered entry is written there; otherwise they are only
// listed.
func decryptArchive(archivePath string, start zipcrypto.Keys, outDir string) int {
	data, err := os.ReadFile(archivePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
		return 2
	}
	results, err := zip.DecryptArchiveWithStart(bytes.NewReader(data), int64(len(data)), start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack kp: --zip: %v\n", err)
		return 2
	}
	if outDir != "" {
		if err := os.MkdirAll(outDir, 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "xcrack kp: --zip-out: %v\n", err)
			return 2
		}
	}
	n := 0
	for _, r := range results {
		if !r.OK {
			continue
		}
		n++
		if outDir == "" {
			fmt.Printf("decrypted: %s (%d bytes)\n", r.Name, len(r.Plaintext))
			continue
		}
		dst := filepath.Join(outDir, filepath.FromSlash(r.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			fmt.Fprintf(os.Stderr, "xcrack kp: --zip-out: %v\n", err)
			return 2
		}
		if err := os.WriteFile(dst, r.Plaintext, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "xcrack kp: --zip-out: %v\n", err)
			return 2
		}
		fmt.Printf("decrypted: %s -> %s (%d bytes)\n", r.Name, dst, len(r.Plaintext))
	}
	if n == 0 {
		fmt.Fprintln(os.Stderr, "xcrack kp: --zip: the recovered key state decrypted no entries (not a ZipCrypto archive, or a different password)")
		return 1
	}
	fmt.Fprintf(os.Stderr, "xcrack kp: --zip: decrypted %d ZipCrypto entr%s from one recovery\n", n, plural(n))
	return 0
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// recoverPassword runs bkcrack's password search from the entry-start key state
// (NewKeys(password)) and prints the recovered password. spec is "MAXLEN:CHARSET".
func recoverPassword(entryStart zipcrypto.Keys, spec, bin string, timeout time.Duration) int {
	maxLenStr, charset, ok := strings.Cut(spec, ":")
	if !ok || charset == "" {
		fmt.Fprintln(os.Stderr, "xcrack kp: --recover-password must be MAXLEN:CHARSET, e.g. 8:?l?d")
		return 2
	}
	maxLen, err := strconv.Atoi(maxLenStr)
	if err != nil || maxLen <= 0 {
		fmt.Fprintf(os.Stderr, "xcrack kp: invalid --recover-password length %q\n", maxLenStr)
		return 2
	}
	fmt.Fprintf(os.Stderr, "xcrack kp: recovering password (<=%d chars, charset %s) via bkcrack\n", maxLen, charset)
	pw, found, err := zipcrypto.ExternalBkcrack{Bin: bin, Timeout: timeout}.RecoverPassword(context.Background(), entryStart, maxLen, charset)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack kp: %v\n", err)
		return 1
	}
	if !found {
		fmt.Fprintln(os.Stderr, "xcrack kp: password not recovered in the given length/charset")
		return 0
	}
	fmt.Printf("password: %s\n", pw)
	return 0
}
