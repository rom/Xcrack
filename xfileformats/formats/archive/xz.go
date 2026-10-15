package archive

import (
	"io"

	"github.com/rom/xfileformats"
	"github.com/ulikunitz/xz"
)

type xzFormat struct{}

func (xzFormat) Name() string            { return "xz" }
func (xzFormat) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

// Detect looks for the xz magic: FD 37 7A 58 5A 00 ("\xfd7zXZ\x00").
func (xzFormat) Detect(p []byte) (float64, bool) {
	if len(p) >= 6 && p[0] == 0xfd && p[1] == '7' && p[2] == 'z' && p[3] == 'X' && p[4] == 'Z' && p[5] == 0x00 {
		return 0.9, true
	}
	return 0, false
}

func (xzFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	if _, err := xz.NewReader(section(r, size)); err != nil {
		return nil, xfileformats.ErrMalformed
	}
	open := func() (io.Reader, error) {
		xr, err := xz.NewReader(section(r, size))
		if err != nil {
			return nil, xfileformats.ErrMalformed
		}
		return io.LimitReader(xr, maxDecompressed), nil
	}
	return oneEntry("content", -1, open), nil
}
