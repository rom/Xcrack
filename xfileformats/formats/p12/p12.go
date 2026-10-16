// Package p12 detects a PKCS#12 (.p12/.pfx) file and recovers its password via
// the PFX MacData MAC (see xcrypto/scheme/p12). On success the PKCS#12 bytes are
// surfaced unchanged (the recovered password is the result). Only the password
// is attacked.
package p12

import (
	"bytes"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xp12 "github.com/rom/xcrypto/scheme/p12"
	"github.com/rom/xfileformats"
)

const maxSize = 1 << 26

// pkcs7-data OID, present near the start of every PFX.
var pkcs7Data = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01}

// Format detects and recovers the password of a PKCS#12 file.
type Format struct{}

// New returns a p12 Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "pkcs12" }

// Caps implements xfileformats.Format: password-protected whole file.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes a DER PFX (SEQUENCE containing the pkcs7-data OID).
func (f *Format) Detect(peek []byte) (float64, bool) {
	if len(peek) > 4 && peek[0] == 0x30 && bytes.Contains(peek, pkcs7Data) {
		return 0.8, true
	}
	return 0, false
}

// Probe parses the PFX MacData and returns a Challenge.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	info, err := xp12.Parse(data)
	if err != nil {
		if errors.Is(err, xp12.ErrNotPFX) {
			return nil, xfileformats.ErrUnknownFormat
		}
		return nil, err
	}
	return xp12.Challenge(info, data), nil
}

// Verify tests a candidate password against the PFX MAC.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	ok, err := xp12.VerifyRaw(ch.Extra["pfx"], password)
	if !ok || err != nil {
		return false, nil, nil
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt surfaces the PKCS#12 bytes unchanged (the recovered password is the
// deliverable; extracting the enclosed key/cert is left to standard tooling).
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(ch.Extra["pfx"]), nil
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
