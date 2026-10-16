// Package iwork recovers the password of a password-protected Apple iWork
// document (Pages, Numbers, Keynote) in the modern "'13+" format (file
// extensions .pages/.numbers/.key; these are ZIP archives of IWA protobuf
// parts). When a document is password-protected the archive carries a `.iwpv2`
// passphrase-verifier blob; this package parses it and tests passphrases against
// it. Only the passphrase is attacked — the document body is not reconstructed.
//
// Verifier scheme (reverse-engineered from Pages/Numbers/Keynote 14.5 files and
// cross-validated against a known passphrase):
//
//	key   = PBKDF2-HMAC-SHA1(passphrase, salt, iterations, 16)   // AES-128
//	plain = AES-128-CBC-decrypt(blob, key, iv)                   // 64 bytes
//	valid = sha256(plain[0:32]) == plain[32:64]
//
// The `.iwpv2` layout (little-endian) is:
//
//	[0:2]   format  (uint16, == 2)
//	[2:4]   variant (uint16, == 1 for the AES-128/SHA-1 scheme above)
//	[4:8]   iterations (uint32)
//	[8:24]  salt (16 bytes)
//	[24:40] iv   (16 bytes)
//	[40:..] blob (AES-CBC ciphertext, multiple of 16, >= 64 bytes)
package iwork

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"github.com/rom/xcrypto"
	"golang.org/x/crypto/pbkdf2"
)

// ErrNotIWork means the data is not a recognizable `.iwpv2` verifier.
var ErrNotIWork = errors.New("iwork: not an iWork password verifier")

// ErrUnsupported means a `.iwpv2` whose format/variant this package does not
// implement (so a caller should not treat a verify miss as a wrong password).
var ErrUnsupported = errors.New("iwork: unsupported iWork verifier variant")

const (
	// VerifierName is the archive member that holds the passphrase verifier.
	VerifierName = ".iwpv2"
	// HintName is the archive member that holds the (plaintext) passphrase hint.
	HintName = ".iwph"

	headerLen = 8
	saltLen   = 16
	ivLen     = 16
	minBlob   = 64 // we read plain[0:64] for verification
	minLen    = headerLen + saltLen + ivLen + minBlob

	keyLen        = 16 // AES-128
	maxIterations = 100_000_000
)

// Params holds the parsed `.iwpv2` fields needed to test a passphrase.
type Params struct {
	Format     uint16
	Variant    uint16
	Iterations int
	Salt       []byte
	IV         []byte
	Blob       []byte
}

// Parse reads a `.iwpv2` verifier blob.
func Parse(iwpv2 []byte) (*Params, error) {
	if len(iwpv2) < minLen {
		return nil, ErrNotIWork
	}
	format := binary.LittleEndian.Uint16(iwpv2[0:2])
	variant := binary.LittleEndian.Uint16(iwpv2[2:4])
	if format != 2 {
		return nil, ErrNotIWork
	}
	if variant != 1 {
		return nil, ErrUnsupported // only the AES-128/SHA-1 scheme is implemented
	}
	iters := int(binary.LittleEndian.Uint32(iwpv2[4:8]))
	if iters <= 0 || iters > maxIterations {
		return nil, ErrUnsupported
	}
	blob := iwpv2[headerLen+saltLen+ivLen:]
	if len(blob) < minBlob || len(blob)%aes.BlockSize != 0 {
		return nil, ErrUnsupported
	}
	return &Params{
		Format:     format,
		Variant:    variant,
		Iterations: iters,
		Salt:       iwpv2[headerLen : headerLen+saltLen],
		IV:         iwpv2[headerLen+saltLen : headerLen+saltLen+ivLen],
		Blob:       blob,
	}, nil
}

// Verify reports whether passphrase satisfies the verifier. It performs the
// (deliberately expensive) PBKDF2 and is safe for concurrent use.
func Verify(p *Params, passphrase []byte) bool {
	key := pbkdf2.Key(passphrase, p.Salt, p.Iterations, keyLen, sha1.New)
	blk, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	plain := make([]byte, len(p.Blob))
	cipher.NewCBCDecrypter(blk, p.IV).CryptBlocks(plain, p.Blob)
	sum := sha256.Sum256(plain[:32])
	return subtle.ConstantTimeCompare(sum[:], plain[32:64]) == 1
}

// VerifyRaw parses iwpv2 and tests passphrase in one call. A non-nil error
// (ErrNotIWork/ErrUnsupported) means the blob could not be interpreted, which a
// caller must not treat as "wrong password".
func VerifyRaw(iwpv2, passphrase []byte) (bool, error) {
	p, err := Parse(iwpv2)
	if err != nil {
		return false, err
	}
	return Verify(p, passphrase), nil
}

// Challenge builds a reporting Challenge for an iWork document.
func Challenge(p *Params) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme: "iwork",
		KDF:    xcrypto.KDFSpec{Algo: "pbkdf2-sha1", Salt: p.Salt, Iterations: p.Iterations},
		Cipher: xcrypto.CipherSpec{Algo: "aes-128-cbc"},
	}
}
