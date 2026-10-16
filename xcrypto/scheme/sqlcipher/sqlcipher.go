// Package sqlcipher recovers the passphrase of a SQLCipher database. SQLCipher
// derives a 256-bit key with PBKDF2 (salt = the first 16 file bytes) and
// authenticates every page with an HMAC keyed by a second PBKDF2 pass. A
// candidate passphrase is confirmed by recomputing page 1's HMAC and comparing
// it to the one stored in the page's reserve — no AES decryption needed.
//
// SQLCipher files have no cleartext magic (the SQLite header itself is
// encrypted), so this scheme cannot be auto-detected from bytes alone; it is a
// library capability for callers that already know a file is a SQLCipher DB
// (e.g. by name or context). Defaults are provided for the common v4 and v3
// profiles, and Params lets a caller set non-default page size / KDF / HMAC.
package sqlcipher

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

// ErrTooSmall means the data is smaller than one SQLCipher page.
var ErrTooSmall = errors.New("sqlcipher: input smaller than one page")

const (
	saltLen = 16
	ivLen   = 16
	keyLen  = 32
	fastKDF = 2 // SQLCipher's fast_kdf_iter for the HMAC subkey
)

// Params describes a SQLCipher cipher profile.
type Params struct {
	PageSize int              // e.g. 4096 (v4) or 1024 (v3)
	KDFIter  int              // e.g. 256000 (v4) or 64000 (v3)
	KDFHash  func() hash.Hash // PBKDF2 PRF: sha512 (v4) or sha1 (v3)
	HMACHash func() hash.Hash // page HMAC: sha512 (v4) or sha1 (v3)
	Name     string
}

// DefaultV4 is the SQLCipher 4 profile.
func DefaultV4() Params {
	return Params{PageSize: 4096, KDFIter: 256000, KDFHash: sha512.New, HMACHash: sha512.New, Name: "sqlcipher4"}
}

// DefaultV3 is the SQLCipher 3 profile.
func DefaultV3() Params {
	return Params{PageSize: 1024, KDFIter: 64000, KDFHash: sha1.New, HMACHash: sha1.New, Name: "sqlcipher3"}
}

// DefaultProfiles returns the profiles to try when the version is unknown.
func DefaultProfiles() []Params { return []Params{DefaultV4(), DefaultV3()} }

// reserveLen is the per-page reserve: IV plus the HMAC digest, rounded up to a
// multiple of the AES block size (16).
func reserveLen(hmacSize int) int {
	r := ivLen + hmacSize
	if r%16 != 0 {
		r = ((r / 16) + 1) * 16
	}
	return r
}

// Verify reports whether password unlocks the database under the given profile,
// by recomputing page 1's HMAC.
func Verify(data, password []byte, p Params) (bool, error) {
	if len(data) < p.PageSize || p.PageSize <= saltLen+ivLen {
		return false, ErrTooSmall
	}
	hmacSize := p.HMACHash().Size()
	reserve := reserveLen(hmacSize)
	if p.PageSize <= saltLen+reserve {
		return false, ErrTooSmall
	}
	salt := data[:saltLen]
	encKey := pbkdf2.Key(password, salt, p.KDFIter, keyLen, p.KDFHash)

	hmacSalt := make([]byte, saltLen)
	for i := range salt {
		hmacSalt[i] = salt[i] ^ 0x3a
	}
	hmacKey := pbkdf2.Key(encKey, hmacSalt, fastKDF, keyLen, p.KDFHash)

	// Page 1 spans [saltLen, PageSize-reserve); its IV and HMAC follow in the reserve.
	ctEnd := p.PageSize - reserve
	ct := data[saltLen:ctEnd]
	iv := data[ctEnd : ctEnd+ivLen]
	stored := data[ctEnd+ivLen : ctEnd+ivLen+hmacSize]

	m := hmac.New(p.HMACHash, hmacKey)
	m.Write(ct)
	m.Write(iv)
	var pg [4]byte
	binary.LittleEndian.PutUint32(pg[:], 1) // page number, 1-based, little-endian
	m.Write(pg[:])
	return hmac.Equal(m.Sum(nil), stored), nil
}

// VerifyAny tries each profile and returns the first that matches (and which).
// A caller whose database uses a non-default PRF/HMAC (e.g. HMAC-SHA256) passes a
// custom Params with crypto/sha256's New.
func VerifyAny(data, password []byte, profiles []Params) (Params, bool) {
	for _, p := range profiles {
		if ok, err := Verify(data, password, p); err == nil && ok {
			return p, true
		}
	}
	return Params{}, false
}
