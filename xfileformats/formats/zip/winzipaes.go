package zip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// This file implements WinZip AES encryption (AE-1 / AE-2), as used by WinZip,
// 7-Zip, and others for AES-encrypted ZIP entries. Key derivation is
// PBKDF2-HMAC-SHA1 with 1000 iterations; the bulk cipher is AES in CTR mode
// with a little-endian block counter starting at 1; integrity is HMAC-SHA1
// truncated to 10 bytes. See the WinZip AES specification.

const (
	aesVendorAE   = 0x4541 // "AE" little-endian as stored
	aesPBKDF2Iter = 1000
	aesMACLen     = 10
)

// aesPWVerifLen is the length of the password-verification value.
const aesPWVerifLen = 2

// aesParams captures the per-entry AES parameters parsed from the 0x9901 extra
// field and the raw entry layout.
type aesParams struct {
	strength     byte   // 1=128, 2=192, 3=256
	actualMethod uint16 // real compression method (0=store, 8=deflate)
	vendorVer    uint16 // 1=AE-1, 2=AE-2
}

func (p aesParams) keyLen() int {
	switch p.strength {
	case 1:
		return 16
	case 2:
		return 24
	case 3:
		return 32
	default:
		return 0
	}
}

func (p aesParams) saltLen() int {
	// salt length is half the key length
	return p.keyLen() / 2
}

func (p aesParams) methodName() string {
	switch p.strength {
	case 1:
		return "winzip-aes-128"
	case 2:
		return "winzip-aes-192"
	case 3:
		return "winzip-aes-256"
	default:
		return "winzip-aes-unknown"
	}
}

var errBadAESExtra = errors.New("zip: malformed WinZip AES extra field")

// parseAESExtra scans the raw extra-field blob for the 0x9901 AES header and
// returns the parameters. It tolerates other extra fields and never reads out
// of bounds.
func parseAESExtra(extra []byte) (aesParams, bool) {
	b := extra
	for len(b) >= 4 {
		id := binary.LittleEndian.Uint16(b[0:2])
		sz := int(binary.LittleEndian.Uint16(b[2:4]))
		if 4+sz > len(b) {
			return aesParams{}, false
		}
		if id == 0x9901 {
			if sz < 7 {
				return aesParams{}, false
			}
			body := b[4 : 4+sz]
			ver := binary.LittleEndian.Uint16(body[0:2])
			vendor := binary.LittleEndian.Uint16(body[2:4])
			if vendor != aesVendorAE {
				return aesParams{}, false
			}
			return aesParams{
				strength:     body[4],
				actualMethod: binary.LittleEndian.Uint16(body[5:7]),
				vendorVer:    ver,
			}, true
		}
		b = b[4+sz:]
	}
	return aesParams{}, false
}

// aesDerive runs PBKDF2-HMAC-SHA1 and splits the output into the encryption
// key, authentication key, and 2-byte password-verification value.
func aesDerive(password, salt []byte, keyLen int) (encKey, authKey, pwVerif []byte, err error) {
	dk, err := pbkdf2.Key(sha1.New, string(password), salt, aesPBKDF2Iter, 2*keyLen+aesPWVerifLen)
	if err != nil {
		return nil, nil, nil, err
	}
	encKey = dk[:keyLen]
	authKey = dk[keyLen : 2*keyLen]
	pwVerif = dk[2*keyLen:]
	return encKey, authKey, pwVerif, nil
}

// aesCTRXor applies AES in WinZip CTR mode to data in place. The counter is a
// 128-bit little-endian integer starting at 1 and incrementing per 16-byte
// block. CTR is symmetric, so this both encrypts and decrypts.
func aesCTRXor(block cipher.Block, data []byte) {
	var ctr [aes.BlockSize]byte
	var ks [aes.BlockSize]byte
	for i := 0; i < len(data); i += aes.BlockSize {
		counter := uint64(i/aes.BlockSize) + 1
		binary.LittleEndian.PutUint64(ctr[0:8], counter)
		// high 8 bytes remain zero (block counts never approach 2^64)
		block.Encrypt(ks[:], ctr[:])
		end := i + aes.BlockSize
		if end > len(data) {
			end = len(data)
		}
		for j := i; j < end; j++ {
			data[j] ^= ks[j-i]
		}
	}
}

// aesVerify checks a password against an AES entry's salt, password-verifier,
// and (authoritatively) the HMAC over the ciphertext.
func aesVerify(password []byte, p aesParams, salt, pwVerif, ciphertext, mac []byte) (bool, error) {
	kl := p.keyLen()
	if kl == 0 {
		return false, errBadAESExtra
	}
	encKey, authKey, wantVerif, err := aesDerive(password, salt, kl)
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(wantVerif, pwVerif) != 1 {
		return false, nil // fast reject (1/65536)
	}
	// Authoritative: HMAC-SHA1 over ciphertext, truncated to 10 bytes.
	m := hmac.New(sha1.New, authKey)
	m.Write(ciphertext)
	sum := m.Sum(nil)[:aesMACLen]
	_ = encKey
	return hmac.Equal(sum, mac), nil
}

// aesDecrypt verifies then decrypts an AES entry, returning the (still
// compressed) plaintext bytes.
func aesDecrypt(password []byte, p aesParams, salt, pwVerif, ciphertext, mac []byte) ([]byte, error) {
	ok, err := aesVerify(password, p, salt, pwVerif, ciphertext, mac)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errWrongPassword
	}
	encKey, _, _, err := aesDerive(password, salt, p.keyLen())
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	copy(out, ciphertext)
	aesCTRXor(block, out)
	return out, nil
}

var errWrongPassword = errors.New("zip: wrong password")
