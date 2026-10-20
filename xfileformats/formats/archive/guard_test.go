package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/nwaples/rardecode/v2"
	"github.com/rom/xfileformats"
)

// szArchive wraps a header blob in the 32-byte 7z signature+start header that
// szWithinSize reads. The two CRCs are left zero: szWithinSize does not check
// them (the library does, later), so these craft just enough to drive the
// pre-scan. NextHeaderOffset is 0, so the blob sits immediately after byte 32.
func szArchive(blob []byte) []byte {
	buf := make([]byte, 32+len(blob))
	copy(buf, []byte("7z\xbc\xaf\x27\x1c"))
	buf[6], buf[7] = 0, 4                                        // format version
	binary.LittleEndian.PutUint64(buf[12:20], 0)                 // NextHeaderOffset
	binary.LittleEndian.PutUint64(buf[20:28], uint64(len(blob))) // NextHeaderSize
	copy(buf[32:], blob)
	return buf
}

// uvarint0xFFFFFFFF is the 7z number encoding of 0xFFFFFFFF (MaxUint32), the
// largest count checkUint64 lets through — enough to drive make([]FileHeader,
// 4.29e9) ≈ 480 GiB in the unguarded library.
var uvarint0xFFFFFFFF = []byte{0xF0, 0xFF, 0xFF, 0xFF, 0xFF}

// TestSevenZipGuardRejectsOversizeFileCount crafts the ~40-byte memory-DoS from
// the audit — a plaintext header (idHeader, idFilesInfo) whose NumFiles is
// MaxUint32 — and checks the pre-scan rejects it before the library allocates.
// The test completing at all is the proof: without the gate the library's
// make([]FileHeader, 0xFFFFFFFF) throws a fatal, unrecoverable out-of-memory.
func TestSevenZipGuardRejectsOversizeFileCount(t *testing.T) {
	blob := append([]byte{szIDHeader, szIDFilesInfo}, uvarint0xFFFFFFFF...)
	blob = append(blob, szIDEnd)
	data := szArchive(blob)

	if err := szWithinSize(bytes.NewReader(data), int64(len(data))); !errors.Is(err, errSzOversizeHeader) {
		t.Fatalf("szWithinSize = %v, want errSzOversizeHeader", err)
	}
	// Entries must refuse it as malformed rather than offer a gated entry.
	es, err := sevenzipFormat{}.Entries(bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, xfileformats.ErrMalformed) {
		t.Fatalf("Entries err = %v (entries %+v), want ErrMalformed", err, es)
	}
}

// TestSevenZipGuardRejectsOversizePackStreams exercises the encoded-header path:
// the outer StreamsInfo is parsed (before any decompression) and its
// NumPackStreams drives a readCRC/readOptionalBool allocation.
func TestSevenZipGuardRejectsOversizePackStreams(t *testing.T) {
	// idEncodedHeader, idPackInfo, packPos=0, NumPackStreams=MaxUint32.
	blob := append([]byte{szIDEncodedHeader, szIDPackInfo, 0x00}, uvarint0xFFFFFFFF...)
	data := szArchive(blob)
	if err := szWithinSize(bytes.NewReader(data), int64(len(data))); !errors.Is(err, errSzOversizeHeader) {
		t.Fatalf("szWithinSize = %v, want errSzOversizeHeader", err)
	}
}

// TestSevenZipGuardAcceptsSaneHeaders is the positive control: the pre-scan must
// stand aside (return nil) for well-formed archives, so it never turns a
// crackable archive away. Covers a minimal plaintext header, the committed
// encoded+header-encrypted fixture, and — when the 7z CLI is present — real
// content-encrypted and plain archives (whose headers the modern tool stores
// compressed, i.e. the idEncodedHeader path).
func TestSevenZipGuardAcceptsSaneHeaders(t *testing.T) {
	sane := szArchive([]byte{szIDHeader, szIDFilesInfo, 0x01, szIDEnd}) // NumFiles=1
	if err := szWithinSize(bytes.NewReader(sane), int64(len(sane))); err != nil {
		t.Fatalf("szWithinSize(sane plaintext header) = %v, want nil", err)
	}

	if data, err := os.ReadFile(filepath.Join("testdata", "hdr.7z")); err == nil {
		if e := szWithinSize(bytes.NewReader(data), int64(len(data))); e != nil {
			t.Fatalf("szWithinSize(hdr.7z) = %v, want nil", e)
		}
	}

	bin, err := exec.LookPath("7z")
	if err != nil {
		return
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "doc.txt"), []byte("real 7z member body"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"a", "-pHunter2", "enc.7z", "doc.txt"},
		{"a", "plain.7z", "doc.txt"},
	} {
		cmd := exec.Command(bin, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("7z %v: %v\n%s", args, err, out)
		}
		data, err := os.ReadFile(filepath.Join(dir, args[len(args)-2]))
		if err != nil {
			t.Fatal(err)
		}
		if e := szWithinSize(bytes.NewReader(data), int64(len(data))); e != nil {
			t.Fatalf("szWithinSize(%s) = %v, want nil (false reject of a real archive)", args[len(args)-2], e)
		}
	}
}

// TestSevenZipGuardStandsAsideOnJunk checks the pre-scan never rejects (or
// panics on) inputs it does not understand — it simply lets the library decide.
func TestSevenZipGuardStandsAsideOnJunk(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":            {},
		"too-short":        []byte("7z\xbc\xaf\x27"),
		"bad-magic":        bytes.Repeat([]byte{0x00}, 64),
		"sig-only":         append([]byte("7z\xbc\xaf\x27\x1c"), bytes.Repeat([]byte{0}, 40)...),
		"unknown-first-id": szArchive([]byte{0x7f, 0x00}),
		"truncated-blob":   szArchive([]byte{szIDHeader, szIDMainStreamsInfo}),
	} {
		if err := szWithinSize(bytes.NewReader(data), int64(len(data))); err != nil {
			t.Errorf("szWithinSize(%s) = %v, want nil (stand aside)", name, err)
		}
	}
}

// TestRarDictionaryCapTightensDefault guards the intent of the RAR fix: all RAR
// readers are built with MaxDictionarySize(maxDecompressed), which only limits
// the per-call decode-window allocation if it is below the library default. If
// maxDecompressed is ever raised above the default the cap becomes a no-op and
// the window-allocation DoS reopens, so fail loudly here. The functional RAR
// tests (TestRarEncrypted, TestHeaderEncryptedRar) confirm the cap does not
// break real archives.
func TestRarDictionaryCapTightensDefault(t *testing.T) {
	if maxDecompressed > rardecode.DefaultMaxDictionarySize {
		t.Fatalf("RAR dictionary cap (maxDecompressed=%d) does not tighten the library default (%d)",
			maxDecompressed, rardecode.DefaultMaxDictionarySize)
	}
}
