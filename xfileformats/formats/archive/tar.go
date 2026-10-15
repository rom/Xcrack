package archive

import (
	stdtar "archive/tar"
	"io"

	"github.com/rom/xfileformats"
)

type tarFormat struct{}

func (tarFormat) Name() string            { return "tar" }
func (tarFormat) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

// Detect looks for the POSIX/GNU "ustar" magic at offset 257.
func (tarFormat) Detect(p []byte) (float64, bool) {
	if len(p) >= 262 && string(p[257:262]) == "ustar" {
		return 0.9, true
	}
	return 0, false
}

func (tarFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	tr := stdtar.NewReader(section(r, size))
	var entries []*xfileformats.Entry
	for callIdx := 0; len(entries) < maxEntries; callIdx++ {
		hdr, err := tr.Next()
		if err != nil {
			break // EOF or truncation: return what we have
		}
		if hdr.Typeflag != stdtar.TypeReg && hdr.Typeflag != stdtar.TypeRegA {
			continue
		}
		name := sanitize(hdr.Name)
		if name == "" {
			continue
		}
		target := callIdx
		entries = append(entries, &xfileformats.Entry{
			Path: name,
			Size: hdr.Size,
			Open: func([]byte) (io.Reader, error) { return tarMember(r, size, target) },
		})
	}
	return entries, nil
}

// tarMember re-opens the archive and returns a streaming reader positioned at
// the member at the given Next() index. Re-scanning keeps memory bounded and is
// safe for concurrent Opens (each gets an independent reader over the immutable
// source).
func tarMember(r io.ReaderAt, size int64, target int) (io.Reader, error) {
	tr := stdtar.NewReader(section(r, size))
	for i := 0; ; i++ {
		_, err := tr.Next()
		if err != nil {
			return nil, xfileformats.ErrMalformed
		}
		if i == target {
			return io.LimitReader(tr, maxDecompressed), nil
		}
	}
}
