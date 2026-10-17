// Package ethwallet detects Ethereum keystore files -- the Web3 Secret Storage
// Definition version 3 JSON written by geth, MetaMask, MyEtherWallet and most
// wallets (the "UTC--...--<address>" files) -- and recovers their passphrase
// via the keystore MAC (see xcrypto/scheme/ethkeystore). Verify-only: the
// recovered passphrase is the deliverable that unlocks the wallet's private
// key; the key itself is not reconstructed here.
package ethwallet

import (
	"bytes"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	eth "github.com/rom/xcrypto/scheme/ethkeystore"
	"github.com/rom/xfileformats"
)

// maxProbe bounds how much of the file is read to parse the keystore JSON.
// Keystores are a few hundred bytes; this stays generous while bounding a
// hostile input.
const maxProbe = 1 << 20

// Format detects and recovers the passphrase of an Ethereum v3 keystore.
type Format struct{}

// New returns an ethwallet Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "ethwallet" }

// Caps implements xfileformats.Format: whole-file password-protected.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes a version-3 keystore by the JSON markers unique to the
// Web3 Secret Storage format. Keystores carry no binary magic, so detection
// keys on the co-occurrence of "ciphertext", "kdf", a known KDF name, and a
// "crypto" object -- a combination no other text file carries.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if len(peek) == 0 || peek[0] != '{' {
		return 0, false
	}
	// Lowercase a copy so capitalized "Crypto"/"KDF" keys still match.
	low := bytes.ToLower(peek)
	if !bytes.Contains(low, []byte(`"crypto"`)) ||
		!bytes.Contains(low, []byte(`"ciphertext"`)) ||
		!bytes.Contains(low, []byte(`"kdf"`)) {
		return 0, false
	}
	if !bytes.Contains(low, []byte(`"scrypt"`)) && !bytes.Contains(low, []byte(`"pbkdf2"`)) {
		return 0, false
	}
	return 0.95, true
}

// Probe parses the keystore JSON once, returning a Challenge that carries the
// document so Verify need not re-read the file.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	n := size
	if n <= 0 {
		return nil, xfileformats.ErrMalformed
	}
	if n > maxProbe {
		n = maxProbe
	}
	buf := make([]byte, n)
	read, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, xfileformats.ErrMalformed
	}
	buf = buf[:read]
	p, err := eth.Parse(buf)
	if err != nil {
		if errors.Is(err, xcrypto.ErrUnsupported) {
			return nil, xfileformats.ErrUnsupported
		}
		return nil, xfileformats.ErrUnknownFormat
	}
	ch := p.Challenge()
	if ch.Extra == nil {
		ch.Extra = map[string][]byte{}
	}
	ch.Extra["keystore"] = append([]byte(nil), buf...)
	return ch, nil
}

// Verify tests one candidate passphrase against the keystore MAC.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	p, err := eth.Parse(ch.Extra["keystore"])
	if err != nil {
		return false, nil, err
	}
	ok, err := eth.Verify(password, p)
	if err != nil || !ok {
		return false, nil, err
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt surfaces the keystore document unchanged. The recovered passphrase is
// the deliverable; the wallet private key is not reconstructed.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(ch.Extra["keystore"]), nil
}
