package xfileformats

import (
	"errors"
	"io"
)

// ErrReadBudget is returned by a budgeted reader when its byte budget is
// exhausted -- the guard against decompression bombs at the format layer.
var ErrReadBudget = errors.New("xfileformats: read budget exceeded")

// BudgetReader wraps an io.Reader and fails once more than Max bytes have been
// read. Formats use it to bound decompression output when the declared size is
// untrusted.
type BudgetReader struct {
	R    io.Reader
	Max  int64
	read int64
}

// NewBudgetReader bounds r to at most max bytes.
func NewBudgetReader(r io.Reader, max int64) *BudgetReader {
	return &BudgetReader{R: r, Max: max}
}

func (b *BudgetReader) Read(p []byte) (int, error) {
	if b.read >= b.Max {
		return 0, ErrReadBudget
	}
	if int64(len(p)) > b.Max-b.read {
		p = p[:b.Max-b.read]
	}
	n, err := b.R.Read(p)
	b.read += int64(n)
	if err == nil && b.read >= b.Max {
		// Allow the caller to observe exactly Max bytes, then fail on next read.
	}
	return n, err
}
