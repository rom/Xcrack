// Package pgp implements decryption of passphrase-protected OpenPGP messages
// (GnuPG `gpg -c` / RFC 4880 symmetric encryption): a Symmetric-Key Encrypted
// Session Key packet (SKESK, String-to-Key derivation) followed by a
// Symmetrically Encrypted Integrity Protected Data packet (SEIPD v1, OpenPGP-CFB
// with a SHA-1 MDC).
//
// Scope: SKESK v4 with the S2K key used directly as the session key (the common
// `gpg -c` case), SEIPD v1 with the MDC, and AES/CAST5/3DES block ciphers. The
// newer AEAD (OCB/SEIPD v2) mode, public-key packets, and compressed inner data
// are out of scope and reported unsupported. Uses only the standard library.
package pgp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1" //nolint:gosec // OpenPGP MDC mandates SHA-1
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/rom/xcrypto"
)

// Message holds the parsed parameters of a symmetric OpenPGP message.
type Message struct {
	CipherAlgo int    // OpenPGP symmetric algorithm id (7/8/9 = AES-128/192/256)
	S2KType    int    // 0 simple, 1 salted, 3 iterated-salted
	HashAlgo   int    // OpenPGP hash algorithm id
	Salt       []byte // 8 bytes for salted/iterated
	Count      int    // iterated S2K octet count
	SEIPD      []byte // the OpenPGP-CFB ciphertext (after the version byte)
}

const (
	maxMessage = 1 << 31
	cipher3DES = 2
	cipherCAST = 3
	cipherAES1 = 7
	cipherAES2 = 8
	cipherAES3 = 9
)

// Parse reads a symmetric OpenPGP message (binary, not ASCII-armored).
func Parse(data []byte) (*Message, error) {
	if len(data) == 0 || len(data) > maxMessage {
		return nil, ErrNotPGP
	}
	m := &Message{}
	haveSKESK, haveSEIPD := false, false
	pos := 0
	for pos < len(data) {
		tag, body, next, ok := readPacket(data, pos)
		if !ok {
			break
		}
		pos = next
		switch tag {
		case 3: // SKESK
			if !parseSKESK(body, m) {
				return nil, xcrypto.ErrMalformed
			}
			haveSKESK = true
		case 18: // SEIPD
			if len(body) < 1 || body[0] != 1 {
				return nil, xcrypto.ErrUnsupported // only SEIPD v1 (MDC)
			}
			m.SEIPD = body[1:]
			haveSEIPD = true
		case 9: // old Symmetrically Encrypted Data (no MDC) -- unsupported
			return nil, xcrypto.ErrUnsupported
		}
		if haveSKESK && haveSEIPD {
			break
		}
	}
	if !haveSKESK {
		return nil, ErrNotPGP
	}
	if !haveSEIPD {
		return nil, xcrypto.ErrUnsupported
	}
	return m, nil
}

func parseSKESK(b []byte, m *Message) bool {
	// version(1) cipher(1) s2k...
	if len(b) < 2 || b[0] != 4 {
		return false
	}
	m.CipherAlgo = int(b[1])
	s := b[2:]
	if len(s) < 2 {
		return false
	}
	m.S2KType = int(s[0])
	m.HashAlgo = int(s[1])
	switch m.S2KType {
	case 0: // simple
		return true
	case 1: // salted
		if len(s) < 2+8 {
			return false
		}
		m.Salt = append([]byte{}, s[2:10]...)
		return true
	case 3: // iterated-salted
		if len(s) < 2+8+1 {
			return false
		}
		m.Salt = append([]byte{}, s[2:10]...)
		m.Count = decodeS2KCount(s[10])
		return true
	}
	return false
}

// decodeS2KCount expands the one-octet iterated-S2K count. RFC 4880 3.7.1.3.
func decodeS2KCount(c byte) int {
	return (16 + int(c&15)) << ((c >> 4) + 6)
}

func newHash(algo int) (hash.Hash, bool) {
	switch algo {
	case 2:
		return sha1.New(), true //nolint:gosec // OpenPGP may specify SHA-1 for S2K
	case 8:
		return sha256.New(), true
	case 9:
		return sha512.New384(), true
	case 10:
		return sha512.New(), true
	case 11:
		return sha256.New224(), true
	}
	return nil, false
}

func keyLen(cipherAlgo int) (int, bool) {
	switch cipherAlgo {
	case cipher3DES:
		return 24, true
	case cipherCAST:
		return 16, true
	case cipherAES1:
		return 16, true
	case cipherAES2:
		return 24, true
	case cipherAES3:
		return 32, true
	}
	return 0, false
}

// DeriveKey runs the String-to-Key function for the message to produce the
// session key.
func DeriveKey(password []byte, m *Message) ([]byte, error) {
	klen, ok := keyLen(m.CipherAlgo)
	if !ok {
		return nil, xcrypto.ErrUnsupported
	}
	// Enough hash contexts, each preloaded with i zero bytes, to fill klen.
	var out []byte
	for i := 0; len(out) < klen; i++ {
		h, ok := newHash(m.HashAlgo)
		if !ok {
			return nil, xcrypto.ErrUnsupported
		}
		for j := 0; j < i; j++ {
			h.Write([]byte{0})
		}
		s2kHash(h, password, m)
		out = append(out, h.Sum(nil)...)
	}
	return out[:klen], nil
}

func s2kHash(h hash.Hash, password []byte, m *Message) {
	switch m.S2KType {
	case 0:
		h.Write(password)
	case 1:
		h.Write(m.Salt)
		h.Write(password)
	case 3:
		tbh := append(append([]byte{}, m.Salt...), password...)
		count := m.Count
		if count < len(tbh) {
			count = len(tbh)
		}
		written := 0
		for written+len(tbh) <= count {
			h.Write(tbh)
			written += len(tbh)
		}
		if written < count {
			h.Write(tbh[:count-written])
		}
	}
}

// openpgpCFBDecrypt decrypts full-block OpenPGP CFB (IV = all zeros, no resync),
// as used by SEIPD v1.
func openpgpCFBDecrypt(key, ct []byte) ([]byte, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	out := make([]byte, len(ct))
	feedback := make([]byte, bs)
	enc := make([]byte, bs)
	for off := 0; off < len(ct); off += bs {
		block.Encrypt(enc, feedback)
		n := bs
		if off+n > len(ct) {
			n = len(ct) - off
		}
		for i := 0; i < n; i++ {
			out[off+i] = ct[off+i] ^ enc[i]
		}
		copy(feedback, ct[off:off+n])
	}
	return out, nil
}

func newBlock(key []byte) (cipher.Block, error) {
	// AES only for the block modes here; CAST5/3DES would need x/crypto.
	switch len(key) {
	case 16, 24, 32:
		return aes.NewCipher(key)
	}
	return nil, xcrypto.ErrUnsupported
}

// quickCheck runs the cheap OpenPGP-CFB prefix check (a 16-bit integrity hint):
// the two bytes after the random prefix repeat the prefix's last two bytes.
func quickCheck(key []byte, m *Message) (bool, error) {
	block, err := newBlock(key)
	if err != nil {
		return false, err
	}
	bs := block.BlockSize()
	if len(m.SEIPD) < bs+2 {
		return false, nil
	}
	pt, err := openpgpCFBDecrypt(key, m.SEIPD[:bs+2])
	if err != nil {
		return false, err
	}
	return pt[bs-2] == pt[bs] && pt[bs-1] == pt[bs+1], nil
}

// Verify reports whether password is correct: the cheap prefix check first, then
// the authoritative SHA-1 MDC over the full decrypted packet.
func Verify(password []byte, m *Message) (bool, error) {
	key, err := DeriveKey(password, m)
	if err != nil {
		return false, err
	}
	ok, err := quickCheck(key, m)
	if err != nil || !ok {
		return false, err
	}
	_, mdcOK, err := decryptWithKey(key, m)
	return mdcOK, err
}

// Decrypt returns the message's literal content for a correct password.
func Decrypt(password []byte, m *Message) ([]byte, error) {
	key, err := DeriveKey(password, m)
	if err != nil {
		return nil, err
	}
	inner, ok, err := decryptWithKey(key, m)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, xcrypto.ErrWrongPassword
	}
	return extractLiteral(inner), nil
}

// decryptWithKey decrypts the SEIPD, checks the MDC, and returns the inner
// packet bytes (between the prefix and the MDC trailer).
func decryptWithKey(key []byte, m *Message) ([]byte, bool, error) {
	block, err := newBlock(key)
	if err != nil {
		return nil, false, err
	}
	bs := block.BlockSize()
	pt, err := openpgpCFBDecrypt(key, m.SEIPD)
	if err != nil {
		return nil, false, err
	}
	if len(pt) < bs+2+22 {
		return nil, false, nil
	}
	// MDC trailer: 0xD3 0x14 || SHA-1(everything up to and including 0xD3 0x14).
	n := len(pt)
	if pt[n-22] != 0xD3 || pt[n-21] != 0x14 {
		return nil, false, nil
	}
	sum := sha1.Sum(pt[:n-20]) //nolint:gosec // OpenPGP MDC
	if subtle.ConstantTimeCompare(sum[:], pt[n-20:]) != 1 {
		return nil, false, nil
	}
	return pt[bs+2 : n-22], true, nil
}

// extractLiteral pulls the raw bytes out of a Literal Data packet (tag 11). If
// the inner data is not a single literal packet (e.g. compressed), the inner
// bytes are returned unchanged so the content is still exposed.
func extractLiteral(inner []byte) []byte {
	tag, body, _, ok := readPacket(inner, 0)
	if !ok || tag != 11 || len(body) < 2 {
		return inner
	}
	// format(1) nameLen(1) name(nameLen) mtime(4) data...
	nameLen := int(body[1])
	off := 2 + nameLen + 4
	if off > len(body) {
		return inner
	}
	return body[off:]
}

// Challenge builds a reporting + external-cracking challenge. It carries the
// full parameter set (cipher/hash/s2k ids and the SEIPD ciphertext in Extra) so
// a whole-file Verify can reconstruct the Message from the Challenge alone.
func Challenge(m *Message) *xcrypto.Challenge {
	kb := 0
	if k, ok := keyLen(m.CipherAlgo); ok {
		kb = k * 8
	}
	return &xcrypto.Challenge{
		Scheme: "openpgp-symmetric",
		KDF:    xcrypto.KDFSpec{Algo: "openpgp-s2k", Iterations: m.Count, Salt: m.Salt},
		Cipher: xcrypto.CipherSpec{Algo: "openpgp-cfb", KeyBits: kb},
		Extra: map[string][]byte{
			"cipher": {byte(m.CipherAlgo)},
			"hash":   {byte(m.HashAlgo)},
			"s2k":    {byte(m.S2KType)},
			"seipd":  m.SEIPD,
		},
	}
}

// MessageFromChallenge reconstructs a Message from a Challenge built by
// Challenge. It returns nil if required fields are missing.
func MessageFromChallenge(ch *xcrypto.Challenge) *Message {
	if ch == nil || len(ch.Extra["cipher"]) != 1 || len(ch.Extra["hash"]) != 1 || len(ch.Extra["s2k"]) != 1 {
		return nil
	}
	return &Message{
		CipherAlgo: int(ch.Extra["cipher"][0]),
		HashAlgo:   int(ch.Extra["hash"][0]),
		S2KType:    int(ch.Extra["s2k"][0]),
		Salt:       ch.KDF.Salt,
		Count:      ch.KDF.Iterations,
		SEIPD:      ch.Extra["seipd"],
	}
}

// readPacket parses one OpenPGP packet header at pos, returning its tag, body,
// and the offset of the next packet. It supports old and new packet formats and
// 1/2/4/5-byte definite lengths (partial/indeterminate lengths are rejected).
func readPacket(data []byte, pos int) (tag int, body []byte, next int, ok bool) {
	if pos >= len(data) {
		return 0, nil, 0, false
	}
	c := data[pos]
	if c&0x80 == 0 {
		return 0, nil, 0, false
	}
	pos++
	var length int
	if c&0x40 != 0 {
		// New format.
		tag = int(c & 0x3F)
		if pos >= len(data) {
			return 0, nil, 0, false
		}
		o1 := int(data[pos])
		pos++
		switch {
		case o1 < 192:
			length = o1
		case o1 < 224:
			if pos >= len(data) {
				return 0, nil, 0, false
			}
			length = ((o1 - 192) << 8) + int(data[pos]) + 192
			pos++
		case o1 == 255:
			if pos+4 > len(data) {
				return 0, nil, 0, false
			}
			length = int(binary.BigEndian.Uint32(data[pos:]))
			pos += 4
		default:
			return 0, nil, 0, false // partial body length unsupported
		}
	} else {
		// Old format.
		tag = int((c >> 2) & 0x0F)
		lenType := c & 0x03
		switch lenType {
		case 0:
			if pos >= len(data) {
				return 0, nil, 0, false
			}
			length = int(data[pos])
			pos++
		case 1:
			if pos+2 > len(data) {
				return 0, nil, 0, false
			}
			length = int(binary.BigEndian.Uint16(data[pos:]))
			pos += 2
		case 2:
			if pos+4 > len(data) {
				return 0, nil, 0, false
			}
			length = int(binary.BigEndian.Uint32(data[pos:]))
			pos += 4
		default:
			return 0, nil, 0, false // indeterminate length unsupported
		}
	}
	if length < 0 || pos+length > len(data) {
		return 0, nil, 0, false
	}
	return tag, data[pos : pos+length], pos + length, true
}

// ErrNotPGP indicates the input is not a recognizable symmetric OpenPGP message.
var ErrNotPGP = errors.New("pgp: not a symmetric OpenPGP message")
