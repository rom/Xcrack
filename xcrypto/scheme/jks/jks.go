// Package jks cracks the store password of a Java KeyStore (JKS). A JKS file
// ends with a 20-byte SHA-1 integrity digest computed over the UTF-16BE store
// password, the constant "Mighty Aphrodite", and the preceding file bytes —
// exactly the check keytool performs for -storepass. Recovering the password is
// therefore a pure SHA-1 comparison (no decryption of the store needed). Only
// the password is attacked; the asymmetric keys inside are never touched.
package jks

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"

	"github.com/rom/xcrypto"
)

// ErrNotJKS means the input is not a Java KeyStore.
var ErrNotJKS = errors.New("jks: not a Java KeyStore")

const (
	magic     = 0xFEEDFEED
	digestLen = 20
	// saltConst is the fixed string Sun's keystore mixes into the integrity hash.
	saltConst = "Mighty Aphrodite"
)

// Info describes a parsed JKS file.
type Info struct {
	Version uint32
	Raw     []byte // whole file (needed to recompute the digest)
}

// Parse validates the JKS magic/version and captures the bytes.
func Parse(data []byte) (*Info, error) {
	if len(data) < 12+digestLen {
		return nil, ErrNotJKS
	}
	if binary.BigEndian.Uint32(data[:4]) != magic {
		return nil, ErrNotJKS
	}
	ver := binary.BigEndian.Uint32(data[4:8])
	if ver != 1 && ver != 2 {
		return nil, ErrNotJKS
	}
	return &Info{Version: ver, Raw: append([]byte(nil), data...)}, nil
}

// Verify reports whether password is the store password, by recomputing the
// trailing SHA-1 integrity digest.
func Verify(raw, password []byte) bool {
	if len(raw) < digestLen {
		return false
	}
	body := raw[:len(raw)-digestLen]
	want := raw[len(raw)-digestLen:]
	h := sha1.New()
	h.Write(utf16be(password))
	h.Write([]byte(saltConst))
	h.Write(body)
	return bytes.Equal(h.Sum(nil), want)
}

// utf16be encodes an ASCII/BMP password as Java's char[] does: each code unit as
// two big-endian bytes.
func utf16be(pw []byte) []byte {
	// Interpret pw as UTF-8 runes; emit UTF-16BE code units.
	out := make([]byte, 0, len(pw)*2)
	for _, r := range string(pw) {
		if r <= 0xFFFF {
			out = append(out, byte(r>>8), byte(r))
		} else {
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			out = append(out, byte(hi>>8), byte(hi), byte(lo>>8), byte(lo))
		}
	}
	return out
}

// Challenge builds a reporting Challenge for a JKS file.
func Challenge(info *Info) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme: "jks",
		KDF:    xcrypto.KDFSpec{Algo: "jks-sha1"},
		Extra:  map[string][]byte{"raw": info.Raw},
	}
}
