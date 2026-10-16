// Package dmg implements password verification for Apple encrypted disk images
// (.dmg), both header versions:
//
//   - v1 ("vilefault" era, AES-128): the password derives a 3DES KEK via
//     PBKDF2-HMAC-SHA1; two RFC-3217-style 3DES key-unwrap blobs must both
//     unwrap with valid PKCS padding at each of their two stages.
//   - v2 (the modern "encrcdsa" container, AES-128 or AES-256): the KEK
//     3DES-decrypts the key blob into an AES key and an HMAC-SHA1 key; the
//     per-chunk IV is HMAC-SHA1(hmacKey, chunkNo); AES-CBC-decrypting the
//     stored data chunk yields plaintext that, for the right password, contains
//     a run of 8 consecutive NUL bytes.
//
// The verification is a faithful reimplementation of John the Ripper's `dmg`
// format and is cross-validated byte-for-byte against John's own authoritative
// test vectors (see dmg_test.go). Verification needs only the fields a real DMG
// header carries (or a dmg2john `$dmg$` line), never the whole image.
package dmg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/prim"
)

// defaultIterations is used when a header/hash line carries no PBKDF2 iteration
// count (John applies the same default for both versions).
const defaultIterations = 1000

// Params are the per-image fields needed to verify a password. Version is 1 or
// 2; the v1 fields (WrappedAESKey/WrappedHMACKey) and the v2 fields
// (IV/EncryptedKeyblob/ChunkNo/Chunk) are mutually exclusive.
type Params struct {
	Version    int
	Salt       []byte
	Iterations int

	// v1
	WrappedAESKey  []byte
	WrappedHMACKey []byte

	// v2
	IV               []byte
	EncryptedKeyblob []byte
	ChunkNo          uint32
	Chunk            []byte
}

func (p Params) iterations() int {
	if p.Iterations <= 0 {
		return defaultIterations
	}
	return p.Iterations
}

// salt20 returns the salt zero-padded/truncated to the fixed 20 bytes John uses
// for the PBKDF2 call regardless of the stored salt length.
func (p Params) salt20() []byte {
	s := make([]byte, 20)
	copy(s, p.Salt)
	return s
}

// SchemeName returns the Challenge scheme identifier for the version.
func (p Params) SchemeName() string {
	if p.Version == 1 {
		return "dmg-v1"
	}
	return "dmg-v2"
}

// Verify reports whether password unlocks the image described by p.
func Verify(password []byte, p Params) (bool, error) {
	dk, err := prim.PBKDF2(sha1.New, string(password), p.salt20(), p.iterations(), 32)
	if err != nil {
		return false, err
	}
	switch p.Version {
	case 1:
		return verifyV1(dk, p)
	case 2:
		return verifyV2(dk, p)
	default:
		return false, xcrypto.ErrUnsupported
	}
}

// verifyV1 accepts when both wrapped blobs unwrap with valid padding, matching
// John's `apple_des3_ede_unwrap_key1` applied to each blob.
func verifyV1(dk []byte, p Params) (bool, error) {
	if len(p.WrappedAESKey) == 0 || len(p.WrappedHMACKey) == 0 {
		return false, nil
	}
	ok1, err := unwrapKey(p.WrappedAESKey, dk)
	if err != nil || !ok1 {
		return false, err
	}
	ok2, err := unwrapKey(p.WrappedHMACKey, dk)
	return ok1 && ok2, err
}

// dmgUnwrapIV is the fixed RFC-3217 3DES key-wrap IV Apple's v1 images use.
var dmgUnwrapIV = []byte{0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05}

// unwrapKey is the two-stage Apple 3DES-EDE key unwrap: decrypt with the fixed
// IV and check PKCS padding, reverse the unpadded bytes, then decrypt the tail
// (IV = its first 8 bytes) and check PKCS padding again. It returns true only
// when both padding checks pass.
func unwrapKey(wrapped, dk []byte) (bool, error) {
	if len(wrapped) == 0 || len(wrapped)%8 != 0 || len(dk) < 24 {
		return false, nil
	}
	block, err := des.NewTripleDESCipher(dk[:24])
	if err != nil {
		return false, err
	}
	temp1 := make([]byte, len(wrapped))
	cipher.NewCBCDecrypter(block, dmgUnwrapIV).CryptBlocks(temp1, wrapped)
	outlen := checkPKCSPad(temp1, 8)
	if outlen < 0 {
		return false, nil
	}
	temp2 := make([]byte, outlen)
	for i := 0; i < outlen; i++ {
		temp2[i] = temp1[outlen-i-1]
	}
	outlen -= 8
	if outlen <= 0 || outlen%8 != 0 {
		return false, nil
	}
	out := make([]byte, outlen)
	cipher.NewCBCDecrypter(block, temp2[:8]).CryptBlocks(out, temp2[8:8+outlen])
	return checkPKCSPad(out, 8) >= 0, nil
}

// verifyV2 3DES-decrypts the key blob, derives the per-chunk AES IV via
// HMAC-SHA1, AES-CBC-decrypts the stored chunk, and accepts when the plaintext
// contains 8 consecutive NUL bytes (John's test).
func verifyV2(dk []byte, p Params) (bool, error) {
	if len(dk) < 24 || len(p.IV) < 8 || len(p.Chunk) < aes.BlockSize {
		return false, nil
	}
	kb := len(p.EncryptedKeyblob)
	if kb < 32 || kb%des.BlockSize != 0 {
		return false, nil
	}
	block, err := des.NewTripleDESCipher(dk[:24])
	if err != nil {
		return false, err
	}
	temp1 := make([]byte, kb)
	cipher.NewCBCDecrypter(block, p.IV[:8]).CryptBlocks(temp1, p.EncryptedKeyblob)

	var cno [4]byte
	binary.LittleEndian.PutUint32(cno[:], p.ChunkNo)
	mac := hmac.New(sha1.New, temp1[:20])
	mac.Write(cno[:])
	iv := mac.Sum(nil) // 20 bytes; first 16 are the AES IV

	var aesKey []byte
	if kb == 48 {
		aesKey = temp1[:16] // AES-128
	} else {
		aesKey = temp1[:32] // AES-256
	}
	ab, err := aes.NewCipher(aesKey)
	if err != nil {
		return false, nil
	}
	// The final data chunk of an image can be a partial AES block; match
	// OpenSSL's AES_cbc_encrypt (as John uses it) by CBC-decrypting only the
	// whole-block portion. The password signal — a run of 8 NUL bytes — lives in
	// those decrypted blocks, so a trailing sub-block is irrelevant.
	full := len(p.Chunk) &^ (aes.BlockSize - 1)
	out := make([]byte, full)
	cipher.NewCBCDecrypter(ab, iv[:aes.BlockSize]).CryptBlocks(out, p.Chunk[:full])
	return hasNConsecutive(out, 0x00, 8), nil
}

// checkPKCSPad validates PKCS#7 padding on a block-aligned buffer and returns
// the unpadded length, or -1 if invalid. It mirrors John's check_pkcs_pad.
func checkPKCSPad(data []byte, blocksize int) int {
	n := len(data)
	if n == 0 || n%blocksize != 0 || n < blocksize {
		return -1
	}
	pad := int(data[n-1])
	if pad > blocksize || pad < 1 {
		return -1
	}
	for i := n - pad; i < n; i++ {
		if int(data[i]) != pad {
			return -1
		}
	}
	return n - pad
}

// hasNConsecutive reports whether b contains a run of at least n bytes equal to v.
func hasNConsecutive(b []byte, v byte, n int) bool {
	run := 0
	for _, c := range b {
		if c == v {
			run++
			if run >= n {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}
