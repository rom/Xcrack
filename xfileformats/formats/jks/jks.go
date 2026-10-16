// Package jks detects a Java KeyStore (JKS) and recovers its store password. The
// password is verified by the store's SHA-1 integrity digest (see
// xcrypto/scheme/jks); on success the keystore bytes are surfaced unchanged (the
// recovered password is the result). Only the password is attacked.
package jks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xjks "github.com/rom/xcrypto/scheme/jks"
	"github.com/rom/xfileformats"
)

const maxSize = 1 << 28

// Format detects and recovers the password of a JKS file.
type Format struct{}

// New returns a jks Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "jks" }

// Caps implements xfileformats.Format: password-protected whole file.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes the JKS magic 0xFEEDFEED.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if len(peek) >= 4 && binary.BigEndian.Uint32(peek[:4]) == 0xFEEDFEED {
		return 0.9, true
	}
	return 0, false
}

// Probe validates the keystore and returns a Challenge.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	info, err := xjks.Parse(data)
	if err != nil {
		if errors.Is(err, xjks.ErrNotJKS) {
			return nil, xfileformats.ErrUnknownFormat
		}
		return nil, err
	}
	return xjks.Challenge(info), nil
}

// Verify tests a candidate store password.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	if xjks.Verify(ch.Extra["raw"], password) {
		return true, append([]byte(nil), password...), nil
	}
	return false, nil, nil
}

// Decrypt surfaces the keystore bytes unchanged (the recovered password is the
// deliverable; the store's asymmetric keys are not touched).
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(ch.Extra["raw"]), nil
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
