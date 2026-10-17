// Package vbaproject recovers the project-protection password of a Microsoft
// VBA project (the "lock project for viewing" password set in the VBA IDE),
// following [MS-OVBA]. The password lives in the DPB field of the PROJECT stream
// of the VBA storage, wrapped in MS-OVBA "Data Encryption" (section 2.4.3) — a
// reversible, keyless obfuscation whose whole purpose, per the spec, is "to
// obfuscate sensitive information, not to secure it".
//
// Decoding the DPB yields one of three cases (MS-OVBA 2.3.1.16 ProjectPassword):
//
//   - No password (Data = {0x00}, Length = 1).
//   - A plaintext password (null-terminated MBCS string) — recovered directly,
//     with NO cracking, like the Access Jet header decode.
//   - A 29-byte Password Hash Data Structure (2.4.4.1) holding a 4-byte Key
//     (salt) and a 20-byte SHA-1 digest PasswordHash = SHA1(password || Key)
//     (2.4.4.4). That is a fast, salted-SHA-1 verifier — one hash per candidate,
//     equivalent to hashcat's sha1($pass.$salt) (mode 110) with a 4-byte hex salt.
//
// The VBA source code itself is never encrypted (tools read it regardless of the
// password), so only the password is the deliverable; nothing is "decrypted".
//
// The Data Encryption transform is implemented in both directions and the pair
// is round-trip tested; the salted-SHA-1 verifier is cross-validated against an
// independent Python reference (the MS-OVBA pseudocode + hashlib) over golden
// DPB fixtures, including hashes and keys that contain embedded NUL bytes.
package vbaproject

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"

	"github.com/rom/xcrypto"
)

// ErrNotVBAPassword means the decoded data is not a recognizable ProjectPassword.
var ErrNotVBAPassword = errors.New("vbaproject: not a VBA project password")

// Kind classifies a decoded ProjectPassword (MS-OVBA 2.3.1.16).
type Kind int

const (
	// KindNone: the project has no protection password.
	KindNone Kind = iota
	// KindPlaintext: the password is stored in the clear (recovered, not cracked).
	KindPlaintext
	// KindHash: the password is stored as a 4-byte-salted SHA-1 (crackable).
	KindHash
)

// Password is the result of decoding a DPB field.
type Password struct {
	Kind Kind
	// Plaintext is the recovered password when Kind == KindPlaintext (the MBCS
	// bytes with the terminating NUL stripped).
	Plaintext []byte
	// Key is the 4-byte salt and Hash the 20-byte SHA-1 digest when Kind == KindHash.
	Key  []byte
	Hash []byte
}

// --- MS-OVBA 2.4.3 Data Encryption (reversible obfuscation) ---

// DecryptData reverses MS-OVBA Encryption (section 2.4.3.2) on an EncryptedData
// byte array and returns the embedded Data. The layout is
//
//	Seed(1) VersionEnc(1) ProjKeyEnc(1) IgnoredEnc(IgnoredLength) DataLengthEnc(4) DataEnc(Length)
//
// where IgnoredLength = (Seed BAND 6) / 2. Version MUST be 2. All byte arithmetic
// is modulo 256 (the spec stores only low-order bits on overflow).
func DecryptData(enc []byte) ([]byte, error) {
	if len(enc) < 7 { // Seed+VersionEnc+ProjKeyEnc + 4 length bytes, zero ignored/data
		return nil, ErrNotVBAPassword
	}
	seed := enc[0]
	versionEnc := enc[1]
	projKeyEnc := enc[2]
	version := seed ^ versionEnc
	if version != 2 {
		return nil, ErrNotVBAPassword
	}
	projKey := seed ^ projKeyEnc

	unencByte1 := projKey
	encByte1 := projKeyEnc
	encByte2 := versionEnc
	pos := 3
	// next decodes one more encrypted byte, advancing the rolling state.
	next := func() (byte, bool) {
		if pos >= len(enc) {
			return 0, false
		}
		byteEnc := enc[pos]
		pos++
		b := byteEnc ^ (encByte2 + unencByte1) // mod 256 via byte wraparound
		encByte2 = encByte1
		encByte1 = byteEnc
		unencByte1 = b
		return b, true
	}

	ignoredLength := int((seed & 6) / 2)
	for i := 0; i < ignoredLength; i++ {
		if _, ok := next(); !ok {
			return nil, ErrNotVBAPassword
		}
	}
	var lenBytes [4]byte
	for i := 0; i < 4; i++ {
		b, ok := next()
		if !ok {
			return nil, ErrNotVBAPassword
		}
		lenBytes[i] = b
	}
	length := binary.LittleEndian.Uint32(lenBytes[:])
	if length > uint32(len(enc)) { // declared length can't exceed the blob (bomb guard)
		return nil, ErrNotVBAPassword
	}
	data := make([]byte, 0, length)
	for i := uint32(0); i < length; i++ {
		b, ok := next()
		if !ok {
			return nil, ErrNotVBAPassword
		}
		data = append(data, b)
	}
	return data, nil
}

// EncryptData applies MS-OVBA Encryption (section 2.4.3.1) to Data, using the
// given seed, projKey and ignored-byte filler. It is the inverse of DecryptData
// and exists so the decode can be round-trip tested and fixtures generated. The
// caller supplies ignored to make output deterministic; IgnoredLength is derived
// from seed exactly as the spec requires.
func EncryptData(data []byte, seed, projKey byte, ignored []byte) []byte {
	const version = 2
	versionEnc := seed ^ version
	projKeyEnc := seed ^ projKey

	out := []byte{seed, versionEnc, projKeyEnc}
	unencByte1 := projKey
	encByte1 := projKeyEnc
	encByte2 := versionEnc
	put := func(plain byte) {
		byteEnc := plain ^ (encByte2 + unencByte1)
		out = append(out, byteEnc)
		encByte2 = encByte1
		encByte1 = byteEnc
		unencByte1 = plain
	}

	ignoredLength := int((seed & 6) / 2)
	for i := 0; i < ignoredLength; i++ {
		var b byte
		if i < len(ignored) {
			b = ignored[i]
		}
		put(b)
	}
	var lenBytes [4]byte
	binary.LittleEndian.PutUint32(lenBytes[:], uint32(len(data)))
	for _, b := range lenBytes {
		put(b)
	}
	for _, b := range data {
		put(b)
	}
	return out
}

// --- MS-OVBA 2.4.4 Password Hash + 2.4.4.2/2.4.4.3 null encoding ---

// decodeNulls reverses Encode Nulls (MS-OVBA 2.4.4.2): a stored 0x01 whose grbit
// bit is clear was originally 0x00; any byte whose grbit bit is set is kept as
// is. grbit bit i (LSB-first) corresponds to stored byte i.
func decodeNulls(stored []byte, grbit uint32) []byte {
	out := make([]byte, len(stored))
	for i, b := range stored {
		if grbit&(1<<uint(i)) == 0 {
			out[i] = 0x00
		} else {
			out[i] = b
		}
	}
	return out
}

// parseHashStructure decodes a 29-byte Password Hash Data Structure (MS-OVBA
// 2.4.4.1) into its Key (4-byte salt) and PasswordHash (20-byte SHA-1). The
// 24-bit grbit field (bytes 1..3, little-endian) packs GrbitKey in bits 0..3 and
// GrbitHashNull in bits 4..23.
func parseHashStructure(d []byte) (key, hash []byte, err error) {
	if len(d) != 29 || d[0] != 0xFF || d[28] != 0x00 {
		return nil, nil, ErrNotVBAPassword
	}
	grbit := uint32(d[1]) | uint32(d[2])<<8 | uint32(d[3])<<16
	grbitKey := grbit & 0x0F
	grbitHash := (grbit >> 4) & 0xFFFFF
	key = decodeNulls(d[4:8], grbitKey)
	hash = decodeNulls(d[8:28], grbitHash)
	return key, hash, nil
}

// Hash computes the MS-OVBA Password Hash (section 2.4.4.4):
// PasswordHash = SHA1(password || key). password must already be in the
// project's MBCS code page (ASCII/UTF-8 ASCII passwords need no conversion).
func Hash(password, key []byte) []byte {
	h := sha1.New()
	h.Write(password)
	h.Write(key)
	return h.Sum(nil)
}

// ParseDPB decodes the raw (already hex-decoded) DPB EncryptedData blob into a
// classified Password.
func ParseDPB(enc []byte) (Password, error) {
	data, err := DecryptData(enc)
	if err != nil {
		return Password{}, err
	}
	switch {
	case len(data) == 1 && data[0] == 0x00:
		return Password{Kind: KindNone}, nil
	case len(data) == 29:
		key, hash, err := parseHashStructure(data)
		if err != nil {
			return Password{}, err
		}
		return Password{Kind: KindHash, Key: key, Hash: hash}, nil
	default:
		// Plaintext password: null-terminated MBCS string.
		pw := data
		if n := len(pw); n > 0 && pw[n-1] == 0x00 {
			pw = pw[:n-1]
		}
		return Password{Kind: KindPlaintext, Plaintext: pw}, nil
	}
}

// Verify reports whether password matches a KindHash ProjectPassword.
func Verify(key, hash, password []byte) bool {
	if len(hash) != 20 || len(key) != 4 {
		return false
	}
	got := Hash(password, key)
	// constant-time not required: hash is public, this is an offline verifier.
	for i := range got {
		if got[i] != hash[i] {
			return false
		}
	}
	return true
}

// Challenge builds a reporting/verification Challenge for a KindHash password.
func Challenge(key, hash []byte) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:   "vba-project",
		KDF:      xcrypto.KDFSpec{Algo: "vba-sha1", Salt: append([]byte(nil), key...)},
		Cipher:   xcrypto.CipherSpec{Algo: "none"},
		Verifier: append([]byte(nil), hash...),
		Extra: map[string][]byte{
			"key":  append([]byte(nil), key...),
			"hash": append([]byte(nil), hash...),
		},
	}
}
