// Package officebinary implements the legacy (pre-OOXML) Microsoft Office
// binary-document encryption schemes defined by [MS-OFFCRYPTO]: the two RC4
// families and the weak XOR obfuscation used by .doc/.xls/.ppt files saved by
// Office 97 through 2003.
//
// Three schemes are covered:
//
//   - RC4 CryptoAPI (Office XP/2003, "strong" encryption): a SHA-1 key
//     derivation with a per-block rekey; key length is taken from the
//     EncryptionHeader. [MS-OFFCRYPTO] 2.3.5.
//   - RC4 (Office 97/2000, "office binary"): an MD5 key derivation producing a
//     128-bit key, also rekeyed per block. [MS-OFFCRYPTO] 2.3.6.
//   - XOR obfuscation (very weak, Excel/Word): a 16-byte XOR key array derived
//     from the password, plus a 16-bit password verifier. [MS-OFFCRYPTO] 2.3.7.
//
// This package performs only the cryptography for a decoded challenge: key
// derivation, password verification, and byte decryption. Locating the
// encryption parameters inside the compound-file streams (the Word FIB, the
// Excel FilePass record, the PowerPoint CryptSession10Container) is the job of
// the file-format layer.
//
// RC4 is a symmetric stream cipher, so the decrypt routines double as encrypt
// routines; the tests exploit this for round-trip coverage.
package officebinary

import (
	"crypto/md5"  //nolint:gosec // MS-OFFCRYPTO mandates MD5/SHA-1/RC4; this decrypts legacy files.
	"crypto/sha1" //nolint:gosec // see above
	"encoding/binary"

	"github.com/rom/xcrypto/prim"
)

// --- RC4 CryptoAPI (Office XP/2003) ------------------------------------------

// CryptoAPIKey derives the RC4 CryptoAPI intermediate key for a block.
// keyBits is the EncryptionHeader KeySize in bits (e.g. 40, 128). A 40-bit key
// is zero-padded to 16 bytes, matching the CryptoAPI provider. [MS-OFFCRYPTO]
// 2.3.5.2.
func CryptoAPIKey(password []byte, salt []byte, keyBits int, block uint32) []byte {
	pw := prim.UTF16LE(password)
	h0 := sha1.Sum(append(append([]byte{}, salt...), pw...)) //nolint:gosec
	var blk [4]byte
	binary.LittleEndian.PutUint32(blk[:], block)
	hfinal := sha1.Sum(append(h0[:], blk[:]...)) //nolint:gosec
	if keyBits == 40 {
		key := make([]byte, 16)
		copy(key, hfinal[:5])
		return key
	}
	n := keyBits / 8
	if n < 1 {
		n = 1
	}
	if n > len(hfinal) {
		n = len(hfinal)
	}
	return append([]byte{}, hfinal[:n]...)
}

// VerifyCryptoAPI reports whether password is correct, using the
// EncryptionVerifier. encVerifier is 16 bytes; encVerifierHash is 20 bytes
// (SHA-1). Both are decrypted with one continuous RC4 keystream (block 0).
// [MS-OFFCRYPTO] 2.3.5.6.
func VerifyCryptoAPI(password, salt []byte, keyBits int, encVerifier, encVerifierHash []byte) (bool, error) {
	if len(encVerifier) != 16 || len(encVerifierHash) != 20 {
		return false, nil
	}
	key := CryptoAPIKey(password, salt, keyBits, 0)
	buf := append(append([]byte{}, encVerifier...), encVerifierHash...)
	dec, err := prim.RC4(key, buf)
	if err != nil {
		return false, err
	}
	sum := sha1.Sum(dec[:16]) //nolint:gosec
	return prim.ConstantTimeEqual(sum[:], dec[16:36]), nil
}

// DecryptCryptoAPI decrypts data in blockSize-byte chunks, rekeying with an
// incrementing block number starting at startBlock. [MS-OFFCRYPTO] 2.3.5.5.
func DecryptCryptoAPI(password, salt []byte, keyBits int, data []byte, blockSize int, startBlock uint32) ([]byte, error) {
	if blockSize <= 0 {
		blockSize = 0x200
	}
	out := make([]byte, 0, len(data))
	block := startBlock
	for off := 0; off < len(data); off += blockSize {
		end := off + blockSize
		if end > len(data) {
			end = len(data)
		}
		key := CryptoAPIKey(password, salt, keyBits, block)
		dec, err := prim.RC4(key, data[off:end])
		if err != nil {
			return nil, err
		}
		out = append(out, dec...)
		block++
	}
	return out, nil
}

// --- RC4 (Office 97/2000) ----------------------------------------------------

// RC4Key derives the Office 97/2000 RC4 128-bit intermediate key for a block.
// [MS-OFFCRYPTO] 2.3.6.1.
func RC4Key(password, salt []byte, block uint32) []byte {
	pw := prim.UTF16LE(password)
	h0 := md5.Sum(pw) //nolint:gosec
	trunc := h0[:5]
	inter := make([]byte, 0, 21*16)
	for i := 0; i < 16; i++ {
		inter = append(inter, trunc...)
		inter = append(inter, salt...)
	}
	h1 := md5.Sum(inter) //nolint:gosec
	trunc2 := h1[:5]
	var blk [4]byte
	binary.LittleEndian.PutUint32(blk[:], block)
	hfinal := md5.Sum(append(append([]byte{}, trunc2...), blk[:]...)) //nolint:gosec
	return append([]byte{}, hfinal[:16]...)
}

// VerifyRC4 reports whether password is correct for the Office 97/2000 scheme.
// encVerifier and encVerifierHash are each 16 bytes; the hash is MD5.
// [MS-OFFCRYPTO] 2.3.6.2.
func VerifyRC4(password, salt, encVerifier, encVerifierHash []byte) (bool, error) {
	if len(encVerifier) != 16 || len(encVerifierHash) != 16 {
		return false, nil
	}
	key := RC4Key(password, salt, 0)
	buf := append(append([]byte{}, encVerifier...), encVerifierHash...)
	dec, err := prim.RC4(key, buf)
	if err != nil {
		return false, err
	}
	sum := md5.Sum(dec[:16]) //nolint:gosec
	return prim.ConstantTimeEqual(sum[:], dec[16:32]), nil
}

// DecryptRC4 decrypts data in blockSize-byte chunks (Office 97/2000), rekeying
// with an incrementing block number from 0. [MS-OFFCRYPTO] 2.3.6.3.
func DecryptRC4(password, salt, data []byte, blockSize int) ([]byte, error) {
	if blockSize <= 0 {
		blockSize = 0x200
	}
	out := make([]byte, 0, len(data))
	var block uint32
	for off := 0; off < len(data); off += blockSize {
		end := off + blockSize
		if end > len(data) {
			end = len(data)
		}
		key := RC4Key(password, salt, block)
		dec, err := prim.RC4(key, data[off:end])
		if err != nil {
			return nil, err
		}
		out = append(out, dec...)
		block++
	}
	return out, nil
}
