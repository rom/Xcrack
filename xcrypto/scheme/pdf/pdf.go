// Package pdf implements the PDF Standard Security Handler: the password-to-key
// derivation, user/owner password verification, per-object key derivation, and
// string/stream decryption for the schemes in common use -- RC4 (V1/V2, R2-R4),
// AESV2 (V4, R4, AES-128-CBC), and AESV3 (V5, R5/R6, AES-256-CBC). It operates
// on a parsed Handler (the fields of a PDF /Encrypt dictionary plus the file
// /ID); it does not parse PDF structure. Decryption of a whole document is done
// by the file-format layer, which supplies the per-object (num, gen) tuples.
package pdf

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/prim"
)

// pad is the 32-byte password padding string (PDF spec, Algorithm 2).
var pad = []byte{
	0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
	0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
}

// Handler holds the parsed Standard Security Handler parameters.
type Handler struct {
	V, R            int   // algorithm version, revision
	Length          int   // file key length in bytes
	P               int32 // permissions
	O, U            []byte
	OE, UE          []byte // R5/R6 only
	ID              []byte // first element of the file /ID
	EncryptMetadata bool
	Cipher          Cipher
}

// Cipher identifies the bulk cipher.
type Cipher int

const (
	CipherRC4 Cipher = iota
	CipherAESV2
	CipherAESV3
)

// Scheme returns a scheme identifier for a Challenge.
func (h *Handler) Scheme() string {
	switch h.Cipher {
	case CipherAESV2:
		return "pdf-aesv2"
	case CipherAESV3:
		return "pdf-aesv3"
	default:
		return "pdf-rc4"
	}
}

func padPassword(pw []byte) []byte {
	out := make([]byte, 32)
	n := copy(out, pw)
	copy(out[n:], pad)
	return out
}

func xorKey(key []byte, b byte) []byte {
	out := make([]byte, len(key))
	for i := range key {
		out[i] = key[i] ^ b
	}
	return out
}

// --- R2-R4 (RC4 / AESV2) ---

func (h *Handler) fileKeyFromUser(pw []byte) []byte {
	n := h.Length
	m := md5.New()
	m.Write(padPassword(pw))
	m.Write(h.O[:32])
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], uint32(h.P))
	m.Write(p[:])
	m.Write(h.ID)
	if h.R >= 4 && !h.EncryptMetadata {
		m.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	d := m.Sum(nil)
	if h.R >= 3 {
		for i := 0; i < 50; i++ {
			s := md5.Sum(d[:n])
			d = s[:]
		}
	}
	return d[:n]
}

func (h *Handler) ownerRC4Key(ownerPw []byte) []byte {
	n := h.Length
	s := md5.Sum(padPassword(ownerPw))
	d := s[:]
	if h.R >= 3 {
		for i := 0; i < 50; i++ {
			s = md5.Sum(d[:n])
			d = s[:]
		}
	}
	return d[:n]
}

func (h *Handler) computeU(fileKey []byte) []byte {
	if h.R == 2 {
		out, _ := prim.RC4(fileKey, pad)
		return out // 32 bytes
	}
	m := md5.New()
	m.Write(pad)
	m.Write(h.ID)
	out, _ := prim.RC4(fileKey, m.Sum(nil)) // 16 bytes
	for i := 1; i <= 19; i++ {
		out, _ = prim.RC4(xorKey(fileKey, byte(i)), out)
	}
	return out // 16 bytes
}

// --- public verification ---

// VerifyUser checks the user password. On success it returns the file key.
func (h *Handler) VerifyUser(pw []byte) (bool, []byte) {
	if h.R >= 5 {
		return h.verifyUserR6(pw)
	}
	key := h.fileKeyFromUser(pw)
	u := h.computeU(key)
	if h.R == 2 {
		if len(h.U) >= 32 && prim.ConstantTimeEqual(u, h.U[:32]) {
			return true, key
		}
		return false, nil
	}
	if len(h.U) >= 16 && prim.ConstantTimeEqual(u[:16], h.U[:16]) {
		return true, key
	}
	return false, nil
}

// VerifyOwner checks the owner password. On success it returns the file key
// (recovered via the user password embedded in /O).
func (h *Handler) VerifyOwner(pw []byte) (bool, []byte) {
	if h.R >= 5 {
		return h.verifyOwnerR6(pw)
	}
	key := h.ownerRC4Key(pw)
	data := append([]byte(nil), h.O[:32]...)
	if h.R == 2 {
		data, _ = prim.RC4(key, data)
	} else {
		for i := 19; i >= 0; i-- {
			data, _ = prim.RC4(xorKey(key, byte(i)), data)
		}
	}
	// data is now the padded user password; verify it as the user password.
	return h.VerifyUser(data)
}

// Verify tries the user password, then the owner password.
func (h *Handler) Verify(pw []byte) (bool, []byte) {
	if ok, k := h.VerifyUser(pw); ok {
		return true, k
	}
	return h.VerifyOwner(pw)
}

// --- per-object key + decryption ---

// ObjectKey derives the key for object (num, gen). For AESV3 the file key is
// used directly.
func (h *Handler) ObjectKey(fileKey []byte, num, gen int) []byte {
	if h.Cipher == CipherAESV3 {
		return fileKey
	}
	m := md5.New()
	m.Write(fileKey)
	m.Write([]byte{byte(num), byte(num >> 8), byte(num >> 16), byte(gen), byte(gen >> 8)})
	if h.Cipher == CipherAESV2 {
		m.Write([]byte{0x73, 0x41, 0x6c, 0x54}) // "sAlT"
	}
	d := m.Sum(nil)
	n := len(fileKey) + 5
	if n > 16 {
		n = 16
	}
	return d[:n]
}

// DecryptData decrypts a string or stream of object (num, gen).
func (h *Handler) DecryptData(fileKey []byte, num, gen int, data []byte) ([]byte, error) {
	key := h.ObjectKey(fileKey, num, gen)
	if h.Cipher == CipherAESV2 || h.Cipher == CipherAESV3 {
		if len(data) < 16 {
			return nil, xcrypto.ErrMalformed
		}
		iv := data[:16]
		ct := data[16:]
		ct = ct[:len(ct)/16*16] // tolerate a non-aligned tail
		if len(ct) == 0 {
			return nil, nil
		}
		plain, err := prim.CBCDecrypt(key, iv, ct)
		if err != nil {
			return nil, err
		}
		return stripPKCS7(plain), nil
	}
	return prim.RC4(key, data)
}

func stripPKCS7(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n < 1 || n > 16 || n > len(b) {
		return b // invalid padding: return as-is
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return b
		}
	}
	return b[:len(b)-n]
}

// --- R5/R6 (AESV3) ---

// hash2B implements Algorithm 2.B (R6). For R5 it is a single SHA-256.
func (h *Handler) hash2B(password, salt, udata []byte) []byte {
	s := sha256.New()
	s.Write(password)
	s.Write(salt)
	s.Write(udata)
	K := s.Sum(nil)
	if h.R < 6 {
		return K
	}
	for round := 0; ; round++ {
		// K1 = (password || K || udata) repeated 64 times
		block := make([]byte, 0, len(password)+len(K)+len(udata))
		block = append(block, password...)
		block = append(block, K...)
		block = append(block, udata...)
		K1 := make([]byte, 0, len(block)*64)
		for i := 0; i < 64; i++ {
			K1 = append(K1, block...)
		}
		E, err := prim.CBCEncrypt(K[:16], K[16:32], K1)
		if err != nil {
			return K[:32]
		}
		mod := 0
		for _, b := range E[:16] {
			mod += int(b)
		}
		switch mod % 3 {
		case 0:
			d := sha256.Sum256(E)
			K = d[:]
		case 1:
			d := sha512.Sum384(E)
			K = d[:]
		case 2:
			d := sha512.Sum512(E)
			K = d[:]
		}
		if round >= 63 && int(E[len(E)-1]) <= round-32 {
			break
		}
	}
	return K[:32]
}

func (h *Handler) verifyUserR6(pw []byte) (bool, []byte) {
	if len(h.U) < 48 || len(h.UE) < 32 {
		return false, nil
	}
	if !prim.ConstantTimeEqual(h.hash2B(pw, h.U[32:40], nil), h.U[0:32]) {
		return false, nil
	}
	ik := h.hash2B(pw, h.U[40:48], nil)
	fk, err := prim.CBCDecrypt(ik, make([]byte, 16), h.UE[:32])
	if err != nil {
		return false, nil
	}
	return true, fk
}

func (h *Handler) verifyOwnerR6(pw []byte) (bool, []byte) {
	if len(h.O) < 48 || len(h.OE) < 32 || len(h.U) < 48 {
		return false, nil
	}
	u48 := h.U[:48]
	if !prim.ConstantTimeEqual(h.hash2B(pw, h.O[32:40], u48), h.O[0:32]) {
		return false, nil
	}
	ik := h.hash2B(pw, h.O[40:48], u48)
	fk, err := prim.CBCDecrypt(ik, make([]byte, 16), h.OE[:32])
	if err != nil {
		return false, nil
	}
	return true, fk
}

// Challenge builds a reporting Challenge for this handler.
func (h *Handler) Challenge() *xcrypto.Challenge {
	algo := "md5-rc4"
	if h.R >= 5 {
		algo = "sha2-aes256"
	}
	ch := &xcrypto.Challenge{
		Scheme:   h.Scheme(),
		KDF:      xcrypto.KDFSpec{Algo: algo, Salt: h.ID, KeyLen: h.Length},
		Cipher:   xcrypto.CipherSpec{Algo: h.Scheme(), KeyBits: h.Length * 8},
		Verifier: h.U,
		Extra:    h.Marshal(),
	}
	return ch
}

// Marshal serializes the handler into a Challenge.Extra map.
func (h *Handler) Marshal() map[string][]byte {
	hdr := make([]byte, 12)
	binary.LittleEndian.PutUint16(hdr[0:], uint16(h.V))
	binary.LittleEndian.PutUint16(hdr[2:], uint16(h.R))
	binary.LittleEndian.PutUint16(hdr[4:], uint16(h.Length))
	binary.LittleEndian.PutUint32(hdr[6:], uint32(h.P))
	var flags byte
	if h.EncryptMetadata {
		flags |= 1
	}
	flags |= byte(h.Cipher) << 1
	hdr[10] = flags
	m := map[string][]byte{"pdfh": hdr, "O": h.O, "U": h.U, "ID": h.ID}
	if h.OE != nil {
		m["OE"] = h.OE
	}
	if h.UE != nil {
		m["UE"] = h.UE
	}
	return m
}

// Unmarshal reconstructs a handler from a Challenge.Extra map.
func Unmarshal(m map[string][]byte) (*Handler, error) {
	hdr := m["pdfh"]
	if len(hdr) < 12 {
		return nil, xcrypto.ErrMalformed
	}
	flags := hdr[10]
	return &Handler{
		V:               int(binary.LittleEndian.Uint16(hdr[0:])),
		R:               int(binary.LittleEndian.Uint16(hdr[2:])),
		Length:          int(binary.LittleEndian.Uint16(hdr[4:])),
		P:               int32(binary.LittleEndian.Uint32(hdr[6:])),
		EncryptMetadata: flags&1 != 0,
		Cipher:          Cipher(flags >> 1 & 0x3),
		O:               m["O"],
		U:               m["U"],
		OE:              m["OE"],
		UE:              m["UE"],
		ID:              m["ID"],
	}, nil
}
