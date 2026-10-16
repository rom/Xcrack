// Package sshkey detects and decrypts passphrase-protected OpenSSH private keys.
// It is a whole-file encrypted format: the passphrase is attacked, and on success
// the decrypted private key is emitted as an unencrypted PKCS#8 PEM. All
// cryptography is delegated to xcrypto/scheme/sshkey.
package sshkey

import (
	"bytes"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xssh "github.com/rom/xcrypto/scheme/sshkey"
	"github.com/rom/xfileformats"
)

const maxSize = 1 << 24 // private keys are small; cap generously

// Format detects and decrypts OpenSSH private keys.
type Format struct{}

// New returns an sshkey Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "openssh-key" }

// Caps implements xfileformats.Format: whole-file encryption.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes the OpenSSH private-key PEM header.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.Contains(peek, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		return 0.97, true
	}
	return 0, false
}

// Probe parses the key header and returns a Challenge, or ErrNotEncrypted for a
// key with no passphrase.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	info, err := xssh.Parse(data)
	if err != nil {
		if errors.Is(err, xssh.ErrNotEncrypted) {
			return nil, xfileformats.ErrNotEncrypted
		}
		return nil, xfileformats.ErrUnknownFormat
	}
	return xssh.Challenge(info), nil
}

// Verify tests a passphrase. It returns no key material (Decrypt re-derives from
// the passphrase), so the returned key is the passphrase itself for Decrypt.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	ok, err := xssh.Verify(ch.Extra["pem"], password)
	if !ok || err != nil {
		return false, nil, err
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt returns the decrypted private key as an unencrypted PKCS#8 PEM. key is
// the verified passphrase (see Verify).
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	out, err := xssh.Decrypt(ch.Extra["pem"], key)
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
