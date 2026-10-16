// Package puttykey detects and recovers the passphrase of PuTTY .ppk private
// keys. It is a whole-file encrypted format; on success the .ppk bytes are
// surfaced unchanged (the recovered passphrase is the result). Cryptography is
// delegated to xcrypto/scheme/puttykey.
package puttykey

import (
	"bytes"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xppk "github.com/rom/xcrypto/scheme/puttykey"
	"github.com/rom/xfileformats"
)

const maxSize = 1 << 24

// Format detects and recovers the passphrase of a PuTTY .ppk key.
type Format struct{}

// New returns a puttykey Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "putty-ppk" }

// Caps implements xfileformats.Format.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes the .ppk header.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.HasPrefix(peek, []byte("PuTTY-User-Key-File-")) {
		return 0.97, true
	}
	return 0, false
}

// Probe parses the key; returns ErrNotEncrypted for an unencrypted .ppk.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	info, err := xppk.Parse(data)
	if err != nil {
		switch {
		case errors.Is(err, xppk.ErrNotEncrypted):
			return nil, xfileformats.ErrNotEncrypted
		case errors.Is(err, xppk.ErrUnsupported):
			return nil, xfileformats.ErrUnsupported
		default:
			return nil, xfileformats.ErrUnknownFormat
		}
	}
	return xppk.Challenge(info, data), nil
}

// Verify tests a candidate passphrase.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	ok, err := xppk.VerifyRaw(ch.Extra["ppk"], password)
	if !ok || err != nil {
		return false, nil, nil
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt surfaces the .ppk bytes unchanged (the recovered passphrase is the
// deliverable).
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(ch.Extra["ppk"]), nil
}

func readAll(r io.ReaderAt, size int64) ([]byte, error) {
	if size <= 0 || size > maxSize {
		return nil, xfileformats.ErrMalformed
	}
	buf := make([]byte, size)
	n, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, xfileformats.ErrMalformed
	}
	return buf[:n], nil
}
