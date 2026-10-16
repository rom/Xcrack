// Package odf implements OpenDocument (ODF) package encryption as used by
// LibreOffice / OpenOffice. An encrypted ODF file is a ZIP whose individual
// entries are DEFLATE-compressed and then encrypted; META-INF/manifest.xml
// describes the per-entry parameters. This package performs the cryptography for
// a single entry given its parameters: derive the key (start-key hash +
// PBKDF2-HMAC-SHA1), decrypt (AES-256-CBC), and verify via the 1K checksum. The
// ZIP container and manifest parsing live in the file-format layer.
//
// Modern ODF 1.2 (AES-256-CBC, SHA-256 start key) and the ODF 1.3 authenticated
// AES-256-GCM variant are supported. The legacy ODF 1.1 Blowfish-CFB scheme is
// detected and reported as unsupported.
package odf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
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

// isAES256GCM reports whether the algorithm is W3C xmlenc11 AES-256-GCM, the
// authenticated mode ODF 1.3 added (http://www.w3.org/2009/xmlenc11#aes256-gcm).
func isAES256GCM(algo string) bool {
	a := strings.ToLower(algo)
	return strings.Contains(a, "aes256-gcm") || strings.Contains(a, "aes-256-gcm")
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
// caller inflates). AES-256-CBC and AES-256-GCM are supported. For GCM a tag
// mismatch (wrong password) is reported as xcrypto.ErrWrongPassword.
func DecryptCompressed(password []byte, p EntryParams, raw []byte) ([]byte, error) {
	key, err := DeriveKey(password, p)
	if err != nil {
		return nil, err
	}
	switch {
	case isAES256GCM(p.Algorithm):
		return decryptGCM(key, p.IV, raw)
	case isAES256CBC(p.Algorithm):
		if len(p.IV) != 16 {
			return nil, xcrypto.ErrMalformed
		}
		n := len(raw) / 16 * 16
		if n == 0 {
			return nil, xcrypto.ErrMalformed
		}
		return prim.CBCDecrypt(key, p.IV, raw[:n])
	default:
		return nil, xcrypto.ErrUnsupported
	}
}

// decryptGCM opens an ODF AES-256-GCM entry: the stored bytes are the
// ciphertext with the 128-bit authentication tag appended (the Go AEAD
// convention), the nonce is the manifest IV (12 bytes). A tag mismatch means
// the wrong key, so it cannot yield a false-positive verification.
func decryptGCM(key, iv, raw []byte) ([]byte, error) {
	if len(iv) == 0 || len(iv) > 16 {
		return nil, xcrypto.ErrMalformed
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, err
	}
	if len(raw) < aead.Overhead() {
		return nil, xcrypto.ErrMalformed
	}
	plain, err := aead.Open(nil, iv, raw, nil)
	if err != nil {
		return nil, xcrypto.ErrWrongPassword
	}
	return plain, nil
}

// Verify checks a password. For GCM the authentication tag is authoritative; for
// CBC it compares the 1K checksum over the compressed data.
func Verify(password []byte, p EntryParams, raw []byte) (bool, error) {
	if isAES256GCM(p.Algorithm) {
		if _, err := DecryptCompressed(password, p, raw); err != nil {
			if errors.Is(err, xcrypto.ErrWrongPassword) {
				return false, nil
			}
			return false, err
		}
		return true, nil
	}
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
	algo, cipherAlgo := "odf-aes256-cbc", "aes-cbc"
	switch {
	case isAES256GCM(p.Algorithm):
		algo, cipherAlgo = "odf-aes256-gcm", "aes-gcm"
	case isAES256CBC(p.Algorithm):
		algo, cipherAlgo = "odf-aes256-cbc", "aes-cbc"
	default:
		algo = "odf-" + p.Algorithm
	}
	return &xcrypto.Challenge{
		Scheme:   algo,
		KDF:      xcrypto.KDFSpec{Algo: "pbkdf2-hmac-sha1", Iterations: p.Iterations, Salt: p.Salt, KeyLen: p.KeySize},
		Cipher:   xcrypto.CipherSpec{Algo: cipherAlgo, KeyBits: p.KeySize * 8},
		Verifier: p.Checksum,
	}
}
