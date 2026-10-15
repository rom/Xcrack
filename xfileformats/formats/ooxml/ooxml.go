// Package ooxml implements detection and decryption of password-protected
// Microsoft Office documents (the agile and standard ECMA-376 schemes). Such a
// file is an OLE/CFB compound file holding an EncryptionInfo stream and an
// EncryptedPackage stream; the decrypted package is an ordinary OOXML ZIP, which
// the engine re-detects and decomposes. Container parsing is delegated to the
// internal cfb package and all cryptography to xcrypto/scheme/ooxml -- this
// package never interprets document content.
package ooxml

import (
	"bytes"
	"fmt"
	"io"

	"github.com/rom/xcrypto"
	xooxml "github.com/rom/xcrypto/scheme/ooxml"
	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/internal/cfb"
)

const (
	streamEncryptionInfo = "EncryptionInfo"
	streamEncryptedPkg   = "EncryptedPackage"
	maxCFB               = 1 << 30 // 1 GiB backstop
)

// Format detects and decrypts encrypted MS Office documents.
type Format struct{}

// New returns an OOXML Format.
func New() *Format { return &Format{} }

// Register adds the OOXML format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "ooxml" }

// Caps implements xfileformats.Format: whole-file encryption, not a container
// (the decrypted package is re-detected as a ZIP).
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect implements xfileformats.Format: any CFB/OLE2 compound file.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if cfb.IsCFB(peek) {
		return 0.7, true
	}
	return 0, false
}

func readAll(r io.ReaderAt, size int64) ([]byte, error) {
	if size <= 0 || size > maxCFB {
		if size > maxCFB {
			return nil, xfileformats.ErrLimitExceeded
		}
		size = 0
	}
	buf := make([]byte, size)
	n, err := io.ReadFull(io.NewSectionReader(r, 0, size), buf)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}

// Probe implements xfileformats.Encrypted: it reads the EncryptionInfo stream,
// validates it, and returns a Challenge carrying it for Verify/Decrypt.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	cf, err := cfb.Open(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
	}
	info, ok := cf.Stream(streamEncryptionInfo)
	if !ok {
		return nil, fmt.Errorf("%w: compound file has no EncryptionInfo (not an encrypted document)", xfileformats.ErrUnsupported)
	}
	parsed, err := xooxml.ParseEncryptionInfo(info)
	if err != nil {
		return nil, err
	}
	ch := parsed.Challenge()
	if ch.Extra == nil {
		ch.Extra = map[string][]byte{}
	}
	ch.Extra["encryptionInfo"] = info
	return ch, nil
}

// Verify implements xfileformats.Encrypted. On success it returns the derived
// package secret key so Decrypt need not repeat the key derivation.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	info, err := infoFromChallenge(ch)
	if err != nil {
		return false, nil, err
	}
	ok, err := info.Verify(password)
	if err != nil || !ok {
		return false, nil, err
	}
	secret, err := info.DeriveSecretKey(password)
	if err != nil {
		return false, nil, err
	}
	return true, secret, nil
}

// Decrypt implements xfileformats.Encrypted: it decrypts the EncryptedPackage
// stream with the secret key and returns the inner OOXML (ZIP) bytes.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	info, err := infoFromChallenge(ch)
	if err != nil {
		return nil, err
	}
	data, err := readAll(r, size)
	if err != nil {
		return nil, err
	}
	cf, err := cfb.Open(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
	}
	pkg, ok := cf.Stream(streamEncryptedPkg)
	if !ok {
		return nil, fmt.Errorf("%w: no EncryptedPackage stream", xfileformats.ErrMalformed)
	}
	plain, err := info.DecryptPackageWithKey(key, pkg)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(plain), nil
}

func infoFromChallenge(ch *xcrypto.Challenge) (*xooxml.Info, error) {
	if ch == nil || ch.Extra == nil || len(ch.Extra["encryptionInfo"]) == 0 {
		return nil, fmt.Errorf("%w: challenge missing EncryptionInfo", xfileformats.ErrMalformed)
	}
	return xooxml.ParseEncryptionInfo(ch.Extra["encryptionInfo"])
}

// BuildEncryptedAgile wraps an inner OOXML package (a ZIP) in an agile-encrypted
// compound file protected by password. It is used for round-trip tests and
// tooling. spinCount should be small in tests.
func BuildEncryptedAgile(password, pkg []byte, spinCount int) ([]byte, error) {
	info, enc, err := xooxml.EncryptAgile(password, pkg, spinCount)
	if err != nil {
		return nil, err
	}
	return cfb.Build([]cfb.StreamEntry{
		{Name: streamEncryptionInfo, Data: info},
		{Name: streamEncryptedPkg, Data: enc},
	}), nil
}
