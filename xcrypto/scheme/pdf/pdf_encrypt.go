package pdf

import (
	"crypto/rand"

	"github.com/rom/xcrypto/prim"
)

// These helpers construct Handlers and encrypt data for tests and tooling,
// mirroring the verification/decryption paths above.

func randN(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func pkcs7pad(b []byte, bs int) []byte {
	n := bs - len(b)%bs
	out := make([]byte, len(b)+n)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// computeO implements Algorithm 3 (/O for R2-R4).
func (h *Handler) computeO(ownerPw, userPw []byte) []byte {
	if len(ownerPw) == 0 {
		ownerPw = userPw
	}
	key := h.ownerRC4Key(ownerPw)
	out, _ := prim.RC4(key, padPassword(userPw))
	if h.R >= 3 {
		for i := 1; i <= 19; i++ {
			out, _ = prim.RC4(xorKey(key, byte(i)), out)
		}
	}
	return out
}

func newRC4Like(user, owner []byte, v, r int, cipher Cipher) (*Handler, []byte) {
	h := &Handler{
		V: v, R: r, Length: 16, P: -3904,
		ID: []byte("0123456789abcdef"), EncryptMetadata: true, Cipher: cipher,
	}
	h.O = h.computeO(owner, user)
	fk := h.fileKeyFromUser(user)
	u := h.computeU(fk)
	h.U = make([]byte, 32) // spec stores 32; only the first 16 matter for R>=3
	copy(h.U, u)
	return h, fk
}

// NewRC4 builds an R3, 128-bit RC4 handler and returns it with the file key.
func NewRC4(user, owner []byte) (*Handler, []byte) { return newRC4Like(user, owner, 2, 3, CipherRC4) }

// NewRC4R2 builds a V1/R2, 40-bit RC4 handler (the classic Acrobat 3-4 scheme)
// and returns it with the 5-byte file key. This is the key-attackable case.
func NewRC4R2(user, owner []byte) (*Handler, []byte) {
	h := &Handler{
		V: 1, R: 2, Length: 5, P: -16,
		ID: []byte("0123456789abcdef"), EncryptMetadata: true, Cipher: CipherRC4,
	}
	h.O = h.computeO(owner, user)
	fk := h.fileKeyFromUser(user)
	h.U = h.computeU(fk) // R2 stores the full 32-byte RC4(fileKey, pad)
	return h, fk
}

// NewAESV2 builds an R4 AES-128 handler and returns it with the file key.
func NewAESV2(user, owner []byte) (*Handler, []byte) {
	return newRC4Like(user, owner, 4, 4, CipherAESV2)
}

// NewAESV3 builds an R6 AES-256 handler and returns it with the (random) file key.
func NewAESV3(user, owner []byte) (*Handler, []byte) {
	h := &Handler{
		V: 5, R: 6, Length: 32, P: -3904,
		ID: []byte("0123456789abcdef"), EncryptMetadata: true, Cipher: CipherAESV3,
	}
	fk := randN(32)
	uVal, uKey := randN(8), randN(8)
	uhash := h.hash2B(user, uVal, nil)
	h.U = append(append(append([]byte{}, uhash...), uVal...), uKey...)
	ue, _ := prim.CBCEncrypt(h.hash2B(user, uKey, nil), make([]byte, 16), fk)
	h.UE = ue

	oVal, oKey := randN(8), randN(8)
	ohash := h.hash2B(owner, oVal, h.U[:48])
	h.O = append(append(append([]byte{}, ohash...), oVal...), oKey...)
	oe, _ := prim.CBCEncrypt(h.hash2B(owner, oKey, h.U[:48]), make([]byte, 16), fk)
	h.OE = oe
	return h, fk
}

// EncryptData encrypts a string or stream for object (num, gen), the inverse of
// DecryptData.
func (h *Handler) EncryptData(fileKey []byte, num, gen int, plain []byte) []byte {
	key := h.ObjectKey(fileKey, num, gen)
	if h.Cipher == CipherRC4 {
		out, _ := prim.RC4(key, plain)
		return out
	}
	iv := randN(16)
	ct, _ := prim.CBCEncrypt(key, iv, pkcs7pad(plain, 16))
	return append(iv, ct...)
}
