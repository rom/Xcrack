// Package privkey detects and decrypts passphrase-protected private keys in PEM
// form (traditional "DEK-Info" keys and PKCS#8 PBES2). It is a whole-file
// encrypted format; on success the decrypted key is emitted as an unencrypted
// PEM. All cryptography is delegated to xcrypto/scheme/privkey.
package privkey

import (
	"bytes"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xpk "github.com/rom/xcrypto/scheme/privkey"
	"github.com/rom/xfileformats"
)

const maxSize = 1 << 24

// Format detects and decrypts encrypted PEM private keys.
type Format struct{}

// New returns a privkey Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "privkey" }

// Caps implements xfileformats.Format: whole-file encryption.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes an encrypted PEM private key (PKCS#8 or DEK-Info), but not
// an OpenSSH key (handled by the sshkey format).
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.Contains(peek, []byte("OPENSSH PRIVATE KEY")) {
		return 0, false
	}
	if bytes.Contains(peek, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----")) ||
		bytes.Contains(peek, []byte("DEK-Info:")) {
		return 0.9, true
	}
	return 0, false
}

// Probe parses the key and returns a Challenge, or ErrNotEncrypted for a plain key.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	info, err := xpk.Parse(data)
	if err != nil {
		switch {
		case errors.Is(err, xpk.ErrNotEncrypted):
			return nil, xfileformats.ErrNotEncrypted
		case errors.Is(err, xpk.ErrUnsupported):
			return nil, xfileformats.ErrUnsupported
		default:
			return nil, xfileformats.ErrUnknownFormat
		}
	}
	return xpk.Challenge(info), nil
}

// Verify tests a passphrase. The returned key material is the passphrase itself
// (Decrypt re-derives from it).
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	ok, err := xpk.Verify(ch.Extra["pem"], password)
	if !ok || err != nil {
		return false, nil, err
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt returns the decrypted key as an unencrypted PEM. key is the verified
// passphrase.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	out, err := xpk.Decrypt(ch.Extra["pem"], key)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(out), nil
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
