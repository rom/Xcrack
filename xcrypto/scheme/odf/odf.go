// Package odf implements OpenDocument (ODF) package encryption as used by
// LibreOffice / OpenOffice. An encrypted ODF file is a ZIP whose individual
// entries are DEFLATE-compressed and then encrypted; META-INF/manifest.xml
// describes the per-entry parameters. This package performs the cryptography for
// a single entry given its parameters: derive the key (start-key hash +
// PBKDF2-HMAC-SHA1), decrypt (AES-256-CBC), and verify via the 1K checksum. The
// ZIP container and manifest parsing live in the file-format layer.
//
// Modern ODF 1.2 (AES-256-CBC, SHA-256 start key) is supported. The legacy
// ODF 1.1 Blowfish-CFB scheme is detected and reported as unsupported.
package odf

import (
	"crypto/sha1"
	"crypto/sha256"
	"strings"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/prim"
)

// EntryParams are the encryption parameters for one ODF entry (from manifest.xml).
type EntryParams struct {
	Algorithm        string // e.g. "...#aes256-cbc", "Blowfish CFB"
	IV               []byte
	Salt             []byte
	Iterations       int
	KeySize          int    // derived key length in bytes
	StartKeyHash     string // "SHA256" / "SHA1"
	Checksum         []byte
	ChecksumType     string // e.g. "...#sha256-1k", "SHA1/1K"
	UncompressedSize int64
}

func isAES256CBC(algo string) bool {
	return strings.Contains(strings.ToLower(algo), "aes256-cbc") || strings.Contains(strings.ToLower(algo), "aes-256-cbc")
}

// DeriveKey computes the content key: PBKDF2-HMAC-SHA1(start-key-hash(password)).
func DeriveKey(password []byte, p EntryParams) ([]byte, error) {
	var start []byte
	switch h := strings.ToLower(p.StartKeyHash); {
	case h == "" || strings.Contains(h, "sha256"):
		s := sha256.Sum256(password)
		start = s[:]
	case strings.Contains(h, "sha1"):
		s := sha1.Sum(password)
		start = s[:]
	default:
		return nil, xcrypto.ErrUnsupported
	}
	keyLen := p.KeySize
	if keyLen <= 0 || keyLen > 32 {
		keyLen = 32
	}
	iter := p.Iterations
	if iter <= 0 || iter > 10_000_000 {
		return nil, xcrypto.ErrUnsupported
	}
	return prim.PBKDF2(sha1.New, string(start), p.Salt, iter, keyLen)
}

// DecryptCompressed decrypts a raw entry to its DEFLATE-compressed bytes (the
// caller inflates). Only AES-256-CBC is supported.
func DecryptCompressed(password []byte, p EntryParams, raw []byte) ([]byte, error) {
	if !isAES256CBC(p.Algorithm) {
		return nil, xcrypto.ErrUnsupported
	}
	key, err := DeriveKey(password, p)
	if err != nil {
		return nil, err
	}
	if len(p.IV) != 16 {
		return nil, xcrypto.ErrMalformed
	}
	n := len(raw) / 16 * 16
	if n == 0 {
		return nil, xcrypto.ErrMalformed
	}
	return prim.CBCDecrypt(key, p.IV, raw[:n])
}

// Verify checks a password via the 1K checksum over the compressed data.
func Verify(password []byte, p EntryParams, raw []byte) (bool, error) {
	comp, err := DecryptCompressed(password, p, raw)
	if err != nil {
		return false, err
	}
	head := comp
	if len(head) > 1024 {
		head = head[:1024]
	}
	var sum []byte
	if strings.Contains(strings.ToLower(p.ChecksumType), "sha256") {
		s := sha256.Sum256(head)
		sum = s[:]
	} else {
		s := sha1.Sum(head)
		sum = s[:]
	}
	if len(p.Checksum) == 0 || len(p.Checksum) > len(sum) {
		return false, nil
	}
	return prim.ConstantTimeEqual(sum[:len(p.Checksum)], p.Checksum), nil
}

// Challenge returns a reporting challenge for an ODF entry.
func Challenge(p EntryParams) *xcrypto.Challenge {
	algo := "odf-aes256-cbc"
	if !isAES256CBC(p.Algorithm) {
		algo = "odf-" + p.Algorithm
	}
	return &xcrypto.Challenge{
		Scheme:   algo,
		KDF:      xcrypto.KDFSpec{Algo: "pbkdf2-hmac-sha1", Iterations: p.Iterations, Salt: p.Salt, KeyLen: p.KeySize},
		Cipher:   xcrypto.CipherSpec{Algo: "aes-cbc", KeyBits: p.KeySize * 8},
		Verifier: p.Checksum,
	}
}
