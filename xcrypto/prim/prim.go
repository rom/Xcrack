// Package prim provides the low-level cryptographic primitives shared by the
// encryption schemes: PBKDF2, AES in the modes used by the supported formats
// (little-endian CTR, CBC, ECB), RC4, the Office iterated-hash key derivation,
// UTF-16LE encoding, and a constant-time compare. Everything here is standard,
// format-agnostic, and reusable.
package prim

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rc4"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"unicode/utf16"
)

// ErrNotBlockAligned is returned by the block-mode helpers for bad input sizes.
var ErrNotBlockAligned = errors.New("prim: input not block-aligned")

// PBKDF2 derives a key using PBKDF2 with the given hash.
func PBKDF2(h func() hash.Hash, password string, salt []byte, iter, keyLen int) ([]byte, error) {
	return pbkdf2.Key(h, password, salt, iter, keyLen)
}

// CTRLittleEndian applies AES-CTR with a 128-bit little-endian block counter
// starting at 1 (the WinZip AES convention) to data in place. CTR is symmetric.
func CTRLittleEndian(key, data []byte) error {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	var ctr [aes.BlockSize]byte
	var ks [aes.BlockSize]byte
	for i := 0; i < len(data); i += aes.BlockSize {
		binary.LittleEndian.PutUint64(ctr[0:8], uint64(i/aes.BlockSize)+1)
		block.Encrypt(ks[:], ctr[:])
		end := i + aes.BlockSize
		if end > len(data) {
			end = len(data)
		}
		for j := i; j < end; j++ {
			data[j] ^= ks[j-i]
		}
	}
	return nil
}

// CBCDecrypt decrypts block-aligned data with AES-CBC.
func CBCDecrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		return nil, ErrNotBlockAligned
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

// CBCEncrypt encrypts block-aligned data with AES-CBC (used by fixtures).
func CBCEncrypt(key, iv, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 || len(iv) != aes.BlockSize {
		return nil, ErrNotBlockAligned
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out, nil
}

// ECBDecrypt decrypts block-aligned data with AES-ECB (Office standard encryption).
func ECBDecrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, ErrNotBlockAligned
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Decrypt(out[i:i+bs], data[i:i+bs])
	}
	return out, nil
}

// ECBEncrypt encrypts block-aligned data with AES-ECB (used by fixtures).
func ECBEncrypt(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(data)%bs != 0 {
		return nil, ErrNotBlockAligned
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += bs {
		block.Encrypt(out[i:i+bs], data[i:i+bs])
	}
	return out, nil
}

// RC4 applies the RC4 stream cipher (symmetric).
func RC4(key, data []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out, nil
}

// UTF16LE encodes a password as UTF-16 little-endian (Office uses this before
// hashing). Input is treated as UTF-8 text.
func UTF16LE(s []byte) []byte {
	u := utf16.Encode([]rune(string(s)))
	out := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

// ConstantTimeEqual reports whether a and b are equal, in constant time.
func ConstantTimeEqual(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// Fit truncates b to n bytes, or pads it to n bytes with pad (Office key/IV
// derivation pads short hashes with 0x36).
func Fit(b []byte, n int, pad byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = pad
	}
	copy(out, b)
	return out
}
