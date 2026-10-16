// Package pgp detects and decrypts passphrase-protected OpenPGP messages
// (GnuPG `gpg -c`). It is a whole-file encrypted format: it parses the OpenPGP
// packets, delegates all cryptography to xcrypto/scheme/pgp, and decrypts the
// literal content with the recovered passphrase. Binary messages only (not
// ASCII-armored); public-key messages are out of scope.
package pgp

import (
	"bytes"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xpgp "github.com/rom/xcrypto/scheme/pgp"
	"github.com/rom/xfileformats"
)

const maxSize = 1 << 31

// Format detects and decrypts symmetric OpenPGP messages.
type Format struct{}

// New returns a pgp Format.
func New() *Format { return &Format{} }

// Register adds the pgp format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "openpgp" }

// Caps implements xfileformats.Format: whole-file encryption.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes a binary OpenPGP message that begins with a Symmetric-Key
// Encrypted Session Key packet (tag 3): 0x8c (old format) or 0xc3 (new format).
func (f *Format) Detect(peek []byte) (float64, bool) {
	if len(peek) >= 2 && (peek[0] == 0x8c || peek[0] == 0xc3) {
		return 0.6, true
	}
	return 0, false
}

// Probe parses the OpenPGP message and returns a Challenge.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	m, err := xpgp.Parse(data)
	if err != nil {
		if errors.Is(err, xpgp.ErrNotPGP) {
			return nil, xfileformats.ErrUnknownFormat
		}
		return nil, xfileformats.ErrUnsupported // AEAD/public-key/compressed
	}
	return xpgp.Challenge(m), nil
}

// Verify tests a passphrase against the message reconstructed from the Challenge.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	m := xpgp.MessageFromChallenge(ch)
	if m == nil {
		return false, nil, xfileformats.ErrMalformed
	}
	ok, err := xpgp.Verify(password, m)
	if !ok {
		return false, nil, err
	}
	// The passphrase is the "key" the whole-file engine carries to Decrypt.
	return true, append([]byte{}, password...), nil
}

// Decrypt decrypts the literal content with the verified passphrase.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	m := xpgp.MessageFromChallenge(ch)
	if m == nil {
		return nil, xfileformats.ErrMalformed
	}
	plain, err := xpgp.Decrypt(key, m)
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
