// Package p12 recovers the password of a PKCS#12 (.p12/.pfx) file. The password
// is verified by the PFX's MacData integrity MAC over the authenticated-safe
// contents — an HMAC whose key comes from the PKCS#12 key-derivation function
// (RFC 7292, Appendix B). This is independent of how the key/cert bags inside are
// encrypted, so it covers both legacy (SHA1-3DES) and modern (PBES2/AES) files.
// Only the password is attacked.
package p12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"errors"
	"hash"

	"github.com/rom/xcrypto"
)

// ErrNotPFX means the input is not a PKCS#12 file (or has no MacData to attack).
var ErrNotPFX = errors.New("p12: not a PKCS#12 file with a password MAC")

var (
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type digestInfo struct {
	Algorithm algorithmIdentifier
	Digest    []byte
}

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type pfx struct {
	Version  int
	AuthSafe contentInfo
	MacData  macData `asn1:"optional"`
}

// Info describes the MAC parameters needed to test a password.
type Info struct {
	authSafe []byte // bytes the MAC is computed over
	mac      []byte // stored MAC digest
	salt     []byte
	iter     int
	newHash  func() hash.Hash
	hashName string
}

// Parse extracts the PFX MacData parameters.
func Parse(data []byte) (*Info, error) {
	var p pfx
	if _, err := asn1.Unmarshal(data, &p); err != nil {
		return nil, ErrNotPFX
	}
	if len(p.MacData.Mac.Digest) == 0 {
		return nil, ErrNotPFX // password-less or MAC-less PFX
	}
	// The MAC is over the VALUE of the authSafe content OCTET STRING.
	var authSafe []byte
	if _, err := asn1.Unmarshal(p.AuthSafe.Content.Bytes, &authSafe); err != nil {
		return nil, ErrNotPFX
	}
	newHash, name := hashFor(p.MacData.Mac.Algorithm.Algorithm)
	if newHash == nil {
		return nil, ErrNotPFX
	}
	iter := p.MacData.Iterations
	if iter <= 0 {
		iter = 1
	}
	return &Info{
		authSafe: authSafe,
		mac:      p.MacData.Mac.Digest,
		salt:     p.MacData.MacSalt,
		iter:     iter,
		newHash:  newHash,
		hashName: name,
	}, nil
}

func hashFor(oid asn1.ObjectIdentifier) (func() hash.Hash, string) {
	switch {
	case oid.Equal(oidSHA256):
		return sha256.New, "sha256"
	case oid.Equal(oidSHA512):
		return sha512.New, "sha512"
	case oid.Equal(oidSHA1):
		return sha1.New, "sha1"
	}
	return nil, ""
}

// Verify reports whether password produces the stored MacData MAC.
func Verify(info *Info, password []byte) bool {
	h := info.newHash()
	u := h.Size()
	bmp := bmpString(password)
	key := pkcs12KDF(info.newHash, 3, bmp, info.salt, info.iter, u)
	m := hmac.New(info.newHash, key)
	m.Write(info.authSafe)
	return hmac.Equal(m.Sum(nil), info.mac)
}

// bmpString encodes a password as a BMPString: UTF-16BE code units followed by a
// two-byte null terminator (as PKCS#12 requires).
func bmpString(pw []byte) []byte {
	out := make([]byte, 0, len(pw)*2+2)
	for _, r := range string(pw) {
		if r > 0xFFFF {
			r = 0xFFFD // replacement; PKCS#12 passwords are effectively BMP
		}
		out = append(out, byte(r>>8), byte(r))
	}
	return append(out, 0, 0)
}

// pkcs12KDF implements the RFC 7292 Appendix B.2 derivation for diversifier id
// (1=key, 2=iv, 3=MAC), producing n bytes.
func pkcs12KDF(newHash func() hash.Hash, id byte, password, salt []byte, iter, n int) []byte {
	h := newHash()
	u := h.Size()
	v := h.BlockSize()

	D := make([]byte, v)
	for i := range D {
		D[i] = id
	}
	S := fill(salt, v)
	P := fill(password, v)
	I := append(append([]byte{}, S...), P...)

	out := make([]byte, 0, n)
	for len(out) < n {
		h.Reset()
		h.Write(D)
		h.Write(I)
		A := h.Sum(nil)
		for i := 1; i < iter; i++ {
			h.Reset()
			h.Write(A)
			A = h.Sum(nil)
		}
		out = append(out, A...)
		if len(out) >= n {
			break
		}
		// B = A repeated to v bytes; I_j = (I_j + B + 1) mod 2^(v*8) per v-block.
		B := fill(A[:u], v)
		for j := 0; j < len(I); j += v {
			addPlusOne(I[j:j+v], B)
		}
	}
	return out[:n]
}

// fill repeats src to the next multiple of blk bytes (empty src -> empty).
func fill(src []byte, blk int) []byte {
	if len(src) == 0 {
		return nil
	}
	nb := ((len(src) + blk - 1) / blk) * blk
	out := make([]byte, nb)
	for i := range out {
		out[i] = src[i%len(src)]
	}
	return out
}

// addPlusOne computes block = (block + add + 1) mod 2^(len*8), big-endian.
func addPlusOne(block, add []byte) {
	carry := 1
	for i := len(block) - 1; i >= 0; i-- {
		s := int(block[i]) + int(add[i]) + carry
		block[i] = byte(s)
		carry = s >> 8
	}
}

// VerifyRaw parses the PFX and tests a password in one call (for callers that
// hold only the raw bytes, e.g. via a Challenge).
func VerifyRaw(data, password []byte) (bool, error) {
	info, err := Parse(data)
	if err != nil {
		return false, err
	}
	return Verify(info, password), nil
}

// Challenge builds a reporting Challenge for a PFX. It carries the raw bytes so a
// caller can re-parse and verify candidates via VerifyRaw.
func Challenge(info *Info, raw []byte) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme: "pkcs12",
		KDF:    xcrypto.KDFSpec{Algo: "pkcs12-" + info.hashName, Iterations: info.iter, Salt: info.salt},
		Extra:  map[string][]byte{"pfx": raw},
	}
}
