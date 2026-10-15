package zip

import "hash/crc32"

// This file implements traditional PKWARE ("ZipCrypto") encryption, as
// specified in APPNOTE.TXT section 6.1. It is weak by modern standards but
// extremely common in the wild, including in malware packaging. We implement
// both decryption (to recover content) and encryption (used only by tests to
// build fixtures without external tools).

var crcTab = crc32.MakeTable(crc32.IEEE)

func crc32update(crc uint32, b byte) uint32 {
	return crcTab[(crc^uint32(b))&0xff] ^ (crc >> 8)
}

// pkKeys is the three-word PKWARE key state.
type pkKeys struct{ k0, k1, k2 uint32 }

func newPkKeys(password []byte) pkKeys {
	k := pkKeys{0x12345678, 0x23456789, 0x34567890}
	for _, b := range password {
		k.update(b)
	}
	return k
}

// update advances the key state using a plaintext byte (true for both the
// encrypt and decrypt directions).
func (k *pkKeys) update(b byte) {
	k.k0 = crc32update(k.k0, b)
	k.k1 = k.k1 + (k.k0 & 0xff)
	k.k1 = k.k1*134775813 + 1
	k.k2 = crc32update(k.k2, byte(k.k1>>24))
}

// streamByte derives the next key-stream byte.
func (k *pkKeys) streamByte() byte {
	temp := (k.k2 | 2) & 0xffff
	return byte((temp * (temp ^ 1)) >> 8)
}

// decrypt decrypts data in place.
func (k *pkKeys) decrypt(data []byte) {
	for i := range data {
		p := data[i] ^ k.streamByte()
		k.update(p)
		data[i] = p
	}
}

// encrypt encrypts data in place (fixtures only).
func (k *pkKeys) encrypt(data []byte) {
	for i := range data {
		p := data[i]
		data[i] = p ^ k.streamByte()
		k.update(p)
	}
}

const pkHeaderLen = 12

// zipCryptoCheckByte returns the expected final header byte for a password
// check. When general-purpose bit 3 is set (streaming / data descriptor), the
// check byte is the high byte of the DOS mod-time; otherwise it is the high
// byte of the CRC-32.
func zipCryptoCheckByte(flags uint16, crc32val uint32, dosTime uint16) byte {
	if flags&0x8 != 0 {
		return byte(dosTime >> 8)
	}
	return byte(crc32val >> 24)
}

// zipCryptoHeaderOK runs the fast (1/256) header-byte check. It decrypts the
// 12-byte header and compares the check byte. It returns the key state
// positioned immediately after the header so the caller can continue
// decrypting the payload without re-initializing.
func zipCryptoHeaderOK(password, raw []byte, flags uint16, crc32val uint32, dosTime uint16) (pkKeys, bool) {
	if len(raw) < pkHeaderLen {
		return pkKeys{}, false
	}
	k := newPkKeys(password)
	hdr := make([]byte, pkHeaderLen)
	copy(hdr, raw[:pkHeaderLen])
	k.decrypt(hdr)
	return k, hdr[pkHeaderLen-1] == zipCryptoCheckByte(flags, crc32val, dosTime)
}
