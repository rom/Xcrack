package prim

import (
	"encoding/binary"
	"hash"
)

// OfficeAgileHash computes the iterated password hash for ECMA-376 agile
// encryption:
//
//	H0 = Hash(salt || passwordUTF16LE)
//	Hn = Hash(LE32(i) || Hn-1)   for i in [0, spinCount)
func OfficeAgileHash(newHash func() hash.Hash, salt, passwordUTF16 []byte, spinCount int) []byte {
	h := newHash()
	h.Write(salt)
	h.Write(passwordUTF16)
	cur := h.Sum(nil)
	var ib [4]byte
	for i := 0; i < spinCount; i++ {
		binary.LittleEndian.PutUint32(ib[:], uint32(i))
		h.Reset()
		h.Write(ib[:])
		h.Write(cur)
		cur = h.Sum(nil)
	}
	return cur
}

// OfficeAgileKey derives a key from the iterated hash and a block key:
//
//	key = Hash(Hfinal || blockKey)   truncated/padded (0x36) to keyLen
func OfficeAgileKey(newHash func() hash.Hash, hfinal, blockKey []byte, keyLen int) []byte {
	h := newHash()
	h.Write(hfinal)
	h.Write(blockKey)
	return Fit(h.Sum(nil), keyLen, 0x36)
}

// OfficeAgileIV derives an IV from a salt and an optional block key:
//
//	iv = blockKey == nil ? salt : Hash(salt || blockKey), fit to blockSize.
func OfficeAgileIV(newHash func() hash.Hash, salt, blockKey []byte, blockSize int) []byte {
	if blockKey == nil {
		return Fit(salt, blockSize, 0x36)
	}
	h := newHash()
	h.Write(salt)
	h.Write(blockKey)
	return Fit(h.Sum(nil), blockSize, 0x36)
}

// OfficeStandardKey derives the AES key for ECMA-376 standard encryption:
//
//	H0 = SHA1(salt || passwordUTF16LE)
//	Hn = SHA1(LE32(i) || Hn-1)   for i in [0, iterations)
//	Hfinal = SHA1(Hn || LE32(0))
//	X1 = SHA1(0x36*64 XOR Hfinal); X2 = SHA1(0x5C*64 XOR Hfinal)
//	key = (X1 || X2)[:keyLen]
func OfficeStandardKey(newHash func() hash.Hash, salt, passwordUTF16 []byte, iterations, keyLen int) []byte {
	h := newHash()
	h.Write(salt)
	h.Write(passwordUTF16)
	cur := h.Sum(nil)
	var ib [4]byte
	for i := 0; i < iterations; i++ {
		binary.LittleEndian.PutUint32(ib[:], uint32(i))
		h.Reset()
		h.Write(ib[:])
		h.Write(cur)
		cur = h.Sum(nil)
	}
	h.Reset()
	h.Write(cur)
	binary.LittleEndian.PutUint32(ib[:], 0)
	h.Write(ib[:])
	hfinal := h.Sum(nil)

	derive := func(pad byte) []byte {
		buf := make([]byte, 64)
		for i := range buf {
			buf[i] = pad
		}
		for i := 0; i < len(hfinal) && i < 64; i++ {
			buf[i] ^= hfinal[i]
		}
		h.Reset()
		h.Write(buf)
		return h.Sum(nil)
	}
	key := append(derive(0x36), derive(0x5c)...)
	if len(key) > keyLen {
		key = key[:keyLen]
	}
	return key
}
