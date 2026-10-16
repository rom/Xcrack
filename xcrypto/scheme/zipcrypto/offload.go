package zipcrypto

// External offload of the ZipCrypto known-plaintext attack.
//
// The in-process RecoverKeys is a complete, verified Biham–Kocher search, but a
// native engine (notably bkcrack, https://github.com/kimci86/bkcrack) runs the
// same search a constant factor faster. An Offloader lets a caller hand the
// problem to such an engine while keeping the exact same API shape and — this is
// the important part — re-validating the engine's answer locally, so an external
// tool can never cause a false positive no matter what it prints.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// Offloader hands the ZipCrypto known-plaintext problem to an external key-
// recovery engine. Recover returns the internal Keys as of just before plain[0],
// exactly as RecoverKeys would, so an offloaded recovery is a drop-in replacement
// for the in-process one. A returned ok=false with a nil error means the engine
// ran but did not find the keys; a non-nil error means the engine could not be
// run or produced output that could not be parsed.
type Offloader interface {
	Recover(plain, cipher []byte) (keys Keys, ok bool, err error)
}

// RecoverKeysWith runs the known-plaintext attack through an external Offloader
// instead of the in-process search. Whatever the engine returns is re-validated
// locally by replaying the keystream over the whole known window, so a buggy or
// hostile engine can never produce a false positive: a result that does not
// reproduce the keystream is reported as not-found. On success the Keys are the
// state just before plain[0], identical to RecoverKeys.
func RecoverKeysWith(plain, cipher []byte, off Offloader) (Keys, bool, error) {
	if off == nil {
		return Keys{}, false, errors.New("zipcrypto: nil Offloader")
	}
	if len(plain) != len(cipher) || len(plain) < MinKnownPlaintext {
		return Keys{}, false, nil
	}
	keys, ok, err := off.Recover(plain, cipher)
	if err != nil || !ok {
		return Keys{}, false, err
	}
	if !keysReproduce(keys, plain, cipher) {
		return Keys{}, false, nil
	}
	return keys, true, nil
}

// keysReproduce reports whether keys reproduce the keystream (plain^cipher) for
// the entire known window — the local check that guards against a false positive.
func keysReproduce(keys Keys, plain, cipher []byte) bool {
	chk := keys
	for i := range plain {
		if chk.streamByte() != plain[i]^cipher[i] {
			return false
		}
		chk.update(plain[i])
	}
	return true
}

// ExternalBkcrack is an Offloader that shells out to a bkcrack binary. It writes
// the known plaintext and its matching ciphertext to temporary files, runs
// bkcrack against them (plaintext aligned at offset 0 of the ciphertext), and
// parses the recovered X Y Z (= key0 key1 key2) from bkcrack's output. bkcrack is
// a separate GPL tool and is NOT bundled or invoked unless a caller sets Bin.
type ExternalBkcrack struct {
	Bin     string        // path or PATH name of the bkcrack binary (required)
	Args    []string      // extra arguments inserted before the -p/-c pair (optional)
	Timeout time.Duration // wall-clock limit for one run (0 => no limit)
	Dir     string        // parent dir for the scratch temp dir (empty => os.TempDir)
}

// bkcrack prints the recovered state as three space-separated 8-hex words (X Y Z)
// on a line of its own, after a "Keys" banner. This matches that triple anywhere
// in the output; the last match is taken (the final reported solution).
var bkcrackKeysRe = regexp.MustCompile(`([0-9a-fA-F]{8})[ \t]+([0-9a-fA-F]{8})[ \t]+([0-9a-fA-F]{8})`)

// Recover implements Offloader. A non-nil error is returned only when bkcrack
// could not be executed or timed out; a clean run that found nothing (bkcrack
// exits non-zero in that case) is reported as ok=false, err=nil.
func (b ExternalBkcrack) Recover(plain, cipher []byte) (Keys, bool, error) {
	if b.Bin == "" {
		return Keys{}, false, errors.New("zipcrypto: ExternalBkcrack.Bin is empty")
	}
	dir, err := os.MkdirTemp(b.Dir, "xcrack-bkcrack-")
	if err != nil {
		return Keys{}, false, err
	}
	defer os.RemoveAll(dir)
	pfile := filepath.Join(dir, "plain.bin")
	cfile := filepath.Join(dir, "cipher.bin")
	if err := os.WriteFile(pfile, plain, 0o600); err != nil {
		return Keys{}, false, err
	}
	if err := os.WriteFile(cfile, cipher, 0o600); err != nil {
		return Keys{}, false, err
	}

	ctx := context.Background()
	if b.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, b.Timeout)
		defer cancel()
	}
	args := append([]string{}, b.Args...)
	args = append(args, "-p", pfile, "-c", cfile)
	cmd := exec.CommandContext(ctx, b.Bin, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	runErr := cmd.Run()

	if keys, ok := parseBkcrackKeys(out.Bytes()); ok {
		return keys, true, nil
	}
	// Parsed no keys. A timeout or a failure to start the process is a real error;
	// bkcrack exiting non-zero because it found nothing is just a miss.
	if runErr != nil {
		if ctx.Err() != nil {
			return Keys{}, false, fmt.Errorf("zipcrypto: bkcrack: %w", ctx.Err())
		}
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			return Keys{}, false, nil // ran, exited non-zero, no keys => miss
		}
		return Keys{}, false, fmt.Errorf("zipcrypto: bkcrack: %w", runErr)
	}
	return Keys{}, false, nil
}

// parseBkcrackKeys extracts the last X Y Z triple from bkcrack's output.
func parseBkcrackKeys(output []byte) (Keys, bool) {
	m := bkcrackKeysRe.FindAllSubmatch(output, -1)
	if len(m) == 0 {
		return Keys{}, false
	}
	last := m[len(m)-1]
	k0, _ := strconv.ParseUint(string(last[1]), 16, 32)
	k1, _ := strconv.ParseUint(string(last[2]), 16, 32)
	k2, _ := strconv.ParseUint(string(last[3]), 16, 32)
	return Keys{k0: uint32(k0), k1: uint32(k1), k2: uint32(k2)}, true
}
