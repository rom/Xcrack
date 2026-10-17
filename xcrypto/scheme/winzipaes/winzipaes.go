// Package winzipaes implements WinZip AES encryption (AE-1 / AE-2) as used for
// AES-encrypted ZIP entries: PBKDF2-HMAC-SHA1 key derivation (1000 iterations),
// AES in WinZip's little-endian CTR mode, and HMAC-SHA1 (truncated to 10 bytes)
// authentication. Both decryption and encryption (for fixtures) are provided.
package winzipaes

import (
	"crypto/hmac"
	"crypto/sha1"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/prim"
)

const (
	// VendorAE is the little-endian "AE" vendor id as stored in the extra field.
	VendorAE   = 0x4541
	PBKDF2Iter = 1000
	PWVerifLen = 2
	MACLen     = 10
)

// Params are the per-entry AES parameters (from the 0x9901 extra field).
type Params struct {
	Strength     byte   // 1=128, 2=192, 3=256
	VendorVer    uint16 // 1=AE-1, 2=AE-2
	ActualMethod uint16 // real compression method (0=store, 8=deflate)
}

// KeyLen returns the encryption key length in bytes.
func (p Params) KeyLen() int {
	switch p.Strength {
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

// SaltLen returns the salt length in bytes (half the key length).
func (p Params) SaltLen() int { return p.KeyLen() / 2 }

// SchemeName returns the scheme identifier for a Challenge.
func (p Params) SchemeName() string {
	switch p.Strength {
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

// Derive runs PBKDF2-HMAC-SHA1 and splits the result into the encryption key,
// authentication key, and 2-byte password-verification value.
func Derive(password, salt []byte, keyLen int) (encKey, authKey, pwVerif []byte, err error) {
	dk, err := prim.PBKDF2(sha1.New, string(password), salt, PBKDF2Iter, 2*keyLen+PWVerifLen)
	if err != nil {
		return nil, nil, nil, err
	}
	return dk[:keyLen], dk[keyLen : 2*keyLen], dk[2*keyLen:], nil
}

// Split divides a raw AES entry into its components.
func Split(p Params, raw []byte) (salt, pwv, ct, mac []byte, err error) {
	sl := p.SaltLen()
	if sl == 0 || len(raw) < sl+PWVerifLen+MACLen {
		return nil, nil, nil, nil, xcrypto.ErrMalformed
	}
	salt = raw[:sl]
	pwv = raw[sl : sl+PWVerifLen]
	ct = raw[sl+PWVerifLen : len(raw)-MACLen]
	mac = raw[len(raw)-MACLen:]
	return salt, pwv, ct, mac, nil
}

// Verify authoritatively checks a password: the 2-byte verifier (fast reject),
// then the HMAC-SHA1 over the ciphertext.
func Verify(password []byte, p Params, raw []byte) (bool, error) {
	salt, pwv, ct, mac, err := Split(p, raw)
	if err != nil {
		return false, err
	}
	_, authKey, wantVerif, err := Derive(password, salt, p.KeyLen())
	if err != nil {
		return false, err
	}
	if !prim.ConstantTimeEqual(wantVerif, pwv) {
		return false, nil
	}
	m := hmac.New(sha1.New, authKey)
	m.Write(ct)
	return hmac.Equal(m.Sum(nil)[:MACLen], mac), nil
}

// VerifyWithDK authoritatively checks a password given the pre-derived PBKDF2
// output dk = PBKDF2-HMAC-SHA1(password, salt, PBKDF2Iter, 2*keyLen+PWVerifLen),
// i.e. with the (expensive) key derivation already performed by an external
// batch tier (the xcrackd OpenCL accelerator). It splits dk into the enc key,
// auth key, and 2-byte verifier exactly as Derive does, then runs the same
// verifier + HMAC check as Verify. The salt the caller derived with must be the
// entry's own salt (raw[:SaltLen]).
func VerifyWithDK(dk []byte, p Params, raw []byte) (bool, error) {
	keyLen := p.KeyLen()
	if keyLen == 0 || len(dk) < 2*keyLen+PWVerifLen {
		return false, xcrypto.ErrMalformed
	}
	_, pwv, ct, mac, err := Split(p, raw)
	if err != nil {
		return false, err
	}
	authKey := dk[keyLen : 2*keyLen]
	wantVerif := dk[2*keyLen : 2*keyLen+PWVerifLen]
	if !prim.ConstantTimeEqual(wantVerif, pwv) {
		return false, nil
	}
	m := hmac.New(sha1.New, authKey)
	m.Write(ct)
	return hmac.Equal(m.Sum(nil)[:MACLen], mac), nil
}

// Decrypt verifies then decrypts a raw AES entry, returning the still-compressed
// plaintext bytes.
func Decrypt(password []byte, p Params, raw []byte) ([]byte, error) {
	salt, pwv, ct, mac, err := Split(p, raw)
	if err != nil {
		return nil, err
	}
	encKey, authKey, wantVerif, err := Derive(password, salt, p.KeyLen())
	if err != nil {
		return nil, err
	}
	if !prim.ConstantTimeEqual(wantVerif, pwv) {
		return nil, xcrypto.ErrWrongPassword
	}
	m := hmac.New(sha1.New, authKey)
	m.Write(ct)
	if !hmac.Equal(m.Sum(nil)[:MACLen], mac) {
		return nil, xcrypto.ErrWrongPassword
	}
	out := make([]byte, len(ct))
	copy(out, ct)
	if err := prim.CTRLittleEndian(encKey, out); err != nil {
		return nil, err
	}
	return out, nil
}

// EncryptRaw builds a raw AES entry (fixtures): salt || pwVerifier || ciphertext
// || mac, for the given compressed payload.
func EncryptRaw(password []byte, p Params, salt, compressed []byte) ([]byte, error) {
	encKey, authKey, pwVerif, err := Derive(password, salt, p.KeyLen())
	if err != nil {
		return nil, err
	}
	ct := make([]byte, len(compressed))
	copy(ct, compressed)
	if err := prim.CTRLittleEndian(encKey, ct); err != nil {
		return nil, err
	}
	m := hmac.New(sha1.New, authKey)
	m.Write(ct)
	mac := m.Sum(nil)[:MACLen]
	out := append([]byte{}, salt...)
	out = append(out, pwVerif...)
	out = append(out, ct...)
	out = append(out, mac...)
	return out, nil
}

// Challenge returns a reporting Challenge for an AES entry.
func Challenge(p Params, salt, pwVerif []byte) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:   p.SchemeName(),
		KDF:      xcrypto.KDFSpec{Algo: "pbkdf2-hmac-sha1", Iterations: PBKDF2Iter, Salt: append([]byte(nil), salt...), KeyLen: p.KeyLen()},
		Cipher:   xcrypto.CipherSpec{Algo: "aes-ctr", KeyBits: p.KeyLen() * 8},
		Verifier: append([]byte(nil), pwVerif...),
	}
}
