// Package archive implements non-encrypted container formats as Xfileformats
// plugins so the engine can unpack them and recurse into their contents: the
// single-stream compressors gzip and bzip2, the tar archive, and MIME (.eml)
// email. Each is a Container; none involves cryptography. Parsing is bounded and
// tolerant (truncated input yields the entries recovered so far, never a panic).
package archive

import (
	stdbzip2 "compress/bzip2"
	stdgzip "compress/gzip"
	"io"
	"path"
	"strings"

	"github.com/rom/xfileformats"
)

const (
	maxEntries            = 100_000
	maxDecompressed int64 = 1 << 30 // 1 GiB backstop per stream; engine refines
)

// Register adds all archive formats to a registry.
func Register(r *xfileformats.Registry) {
	r.Register(gzipFormat{})
	r.Register(bzip2Format{})
	r.Register(xzFormat{})
	r.Register(sevenzipFormat{})
	r.Register(rarFormat{})
	r.Register(tarFormat{})
	r.Register(emlFormat{})
}

func sanitize(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}

func section(r io.ReaderAt, size int64) *io.SectionReader { return io.NewSectionReader(r, 0, size) }

// oneEntry builds a Container with a single decompressed entry.
func oneEntry(name string, size int64, open func() (io.Reader, error)) []*xfileformats.Entry {
	if name == "" {
		name = "content"
	}
	return []*xfileformats.Entry{{
		Path: sanitize(name),
		Size: size,
		Open: func([]byte) (io.Reader, error) { return open() },
	}}
}

// --- gzip ---

type gzipFormat struct{}

func (gzipFormat) Name() string            { return "gzip" }
func (gzipFormat) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }
func (gzipFormat) Detect(p []byte) (float64, bool) {
	if len(p) >= 2 && p[0] == 0x1f && p[1] == 0x8b {
		return 0.9, true
	}
	return 0, false
}

func (gzipFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	zr, err := stdgzip.NewReader(section(r, size))
	if err != nil {
		return nil, xfileformats.ErrMalformed
	}
	name := zr.Name
	if name == "" {
		name = "content"
	}
	zr.Close()
	open := func() (io.Reader, error) {
		gr, err := stdgzip.NewReader(section(r, size))
		if err != nil {
			return nil, xfileformats.ErrMalformed
		}
		return io.LimitReader(gr, maxDecompressed), nil
	}
	return oneEntry(name, -1, open), nil
}

// --- bzip2 (decompress-only in the standard library) ---

type bzip2Format struct{}

func (bzip2Format) Name() string            { return "bzip2" }
func (bzip2Format) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }
func (bzip2Format) Detect(p []byte) (float64, bool) {
	if len(p) >= 4 && p[0] == 'B' && p[1] == 'Z' && p[2] == 'h' && p[3] >= '1' && p[3] <= '9' {
		return 0.9, true
	}
	return 0, false
}

func (bzip2Format) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	open := func() (io.Reader, error) {
		return io.LimitReader(stdbzip2.NewReader(section(r, size)), maxDecompressed), nil
	}
	return oneEntry("content", -1, open), nil
}
