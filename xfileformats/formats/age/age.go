// Package age detects and decrypts passphrase-protected age files
// (age-encryption.org/v1, the "scrypt" recipient). It is a whole-file encrypted
// format: it parses the header, delegates all cryptography to
// xcrypto/scheme/age, and decrypts the payload with the recovered passphrase.
// Public-key (X25519) age files are detected but reported unsupported -- they
// need a private key, not a password.
package age

import (
	"bytes"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xage "github.com/rom/xcrypto/scheme/age"
	"github.com/rom/xfileformats"
)

const maxSize = 1 << 31

// Format detects and decrypts age files.
type Format struct{}

// New returns an age Format.
func New() *Format { return &Format{} }

// Register adds the age format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "age" }

// Caps implements xfileformats.Format: whole-file encryption.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes the age v1 header line.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.HasPrefix(peek, []byte(xage.Magic+"\n")) {
		return 0.95, true
	}
	return 0, false
}

// Probe parses the age header and returns a Challenge for the scrypt stanza.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	p, err := xage.Parse(data)
	if err != nil {
		if errors.Is(err, xage.ErrNotAge) {
			return nil, xfileformats.ErrUnknownFormat
		}
		return nil, xfileformats.ErrUnsupported // e.g. public-key age (no passphrase)
	}
	return xage.Challenge(p), nil
}

// Verify derives the age file key from a passphrase. The returned key is the
// 16-byte file key, which Decrypt uses directly.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	p := &xage.Params{
		Salt:       ch.KDF.Salt,
		LogN:       ch.KDF.Iterations,
		WrappedKey: ch.Extra["wrapped_key"],
	}
	key, ok, err := xage.FileKey(password, p)
	return ok, key, err
}

// Decrypt decrypts the payload with a verified file key.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	p, err := xage.Parse(data)
	if err != nil {
		return nil, xfileformats.ErrMalformed
	}
	plain, err := xage.Decrypt(key, p)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(plain), nil
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
