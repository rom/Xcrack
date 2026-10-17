package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The output result cache (--reuse-output) records, in each per-source output
// directory, a small .xcrack-stamp of the source's content hash, the candidate
// signature, and the recovered passwords. On a repeat run it lets the CLI skip a
// source entirely — no verification KDF, no decrypt, no decompose, no re-write —
// when the already-extracted output is still valid. This is the piece
// --found-cache does NOT do: that cache only reorders candidates so the known
// password is tried first, but every run still re-verifies and re-extracts.

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func reuseStampDir(out, file, suffix string) string {
	return filepath.Join(out, filepath.Base(file)+suffix)
}

func reuseStampPath(out, file, suffix string) string {
	return filepath.Join(reuseStampDir(out, file, suffix), ".xcrack-stamp")
}

// writeReuseStamp records the stamp after a source has been (re-)extracted.
func writeReuseStamp(out, file, suffix, hash, sig string, pws []string) {
	dir := reuseStampDir(out, file, suffix)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	var b strings.Builder
	b.WriteString("hash=" + hash + "\n")
	b.WriteString("sig=" + sig + "\n")
	for _, p := range pws {
		// Quote so a password containing a newline (or any control byte) stays on
		// one line and round-trips exactly; a raw "pw=" + p would split across
		// lines and corrupt/truncate the value on read.
		b.WriteString("pw=" + strconv.Quote(p) + "\n")
	}
	_ = os.WriteFile(reuseStampPath(out, file, suffix), []byte(b.String()), 0o600)
}

// readReuseStamp returns the recovered passwords and ok=true when a valid stamp
// exists for file: the source's current content hash and the candidate signature
// both match what was recorded. Any mismatch (edited file, changed candidate set,
// missing stamp, unreadable source) returns ok=false so the source is searched.
func readReuseStamp(out, file, suffix, sig string) ([]string, bool) {
	data, err := os.ReadFile(reuseStampPath(out, file, suffix))
	if err != nil {
		return nil, false
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, false
	}
	wantHash := sha256hex(src)
	var stampHash, stampSig string
	var pws []string
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "hash="):
			stampHash = line[len("hash="):]
		case strings.HasPrefix(line, "sig="):
			stampSig = line[len("sig="):]
		case strings.HasPrefix(line, "pw="):
			raw := line[len("pw="):]
			if s, err := strconv.Unquote(raw); err == nil {
				pws = append(pws, s)
			} else {
				pws = append(pws, raw) // tolerate a legacy unquoted stamp
			}
		}
	}
	if stampHash == wantHash && stampSig == sig {
		return pws, true
	}
	return nil, false
}
