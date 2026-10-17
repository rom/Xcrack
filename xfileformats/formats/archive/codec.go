package archive

// Additional single-stream compressors, so the engine can recurse into files
// wrapped in a modern codec (most importantly .tar.zst / .tar.lz4, where the
// inner tar — and any encrypted file in it — was previously unreachable). Each
// is a Container with one decompressed entry, mirroring gzip/xz/bzip2; the
// decoders are pure Go (already in the module via sevenzip), so the default
// cgo-free build is unaffected. Output is bounded by maxDecompressed and the
// engine's budgets, and decode errors surface as recovered-so-far / ErrMalformed
// rather than a panic.

import (
	"io"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/rom/xfileformats"
)

// --- zstd (RFC 8878); magic 28 B5 2F FD, plus skippable-frame magics 2*M N ---

type zstdFormat struct{}

func (zstdFormat) Name() string            { return "zstd" }
func (zstdFormat) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }
func (zstdFormat) Detect(p []byte) (float64, bool) {
	if len(p) >= 4 && p[0] == 0x28 && p[1] == 0xb5 && p[2] == 0x2f && p[3] == 0xfd {
		return 0.9, true
	}
	// Skippable frames: 0x184D2A50..0x184D2A5F little-endian (50..5F 2A 4D 18).
	if len(p) >= 4 && p[0] >= 0x50 && p[0] <= 0x5f && p[1] == 0x2a && p[2] == 0x4d && p[3] == 0x18 {
		return 0.85, true
	}
	return 0, false
}

func (zstdFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	// Validate up front so a non-zstd match is rejected before an entry is built.
	// Concurrency 1 keeps the streaming decoder synchronous (no background
	// goroutine), matching the unclosed-reader pattern of the other codecs.
	zr, err := zstd.NewReader(section(r, size), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil, xfileformats.ErrMalformed
	}
	zr.Close()
	open := func() (io.Reader, error) {
		d, err := zstd.NewReader(section(r, size), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, xfileformats.ErrMalformed
		}
		return io.LimitReader(d, maxDecompressed), nil
	}
	return oneEntry("content", -1, open), nil
}

// --- lz4 frame format; magic 04 22 4D 18 ---

type lz4Format struct{}

func (lz4Format) Name() string            { return "lz4" }
func (lz4Format) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }
func (lz4Format) Detect(p []byte) (float64, bool) {
	if len(p) >= 4 && p[0] == 0x04 && p[1] == 0x22 && p[2] == 0x4d && p[3] == 0x18 {
		return 0.9, true
	}
	return 0, false
}

func (lz4Format) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	open := func() (io.Reader, error) {
		return io.LimitReader(lz4.NewReader(section(r, size)), maxDecompressed), nil
	}
	return oneEntry("content", -1, open), nil
}
