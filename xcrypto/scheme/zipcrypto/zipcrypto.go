// Package zipcrypto implements traditional PKWARE ("ZipCrypto") encryption
// (APPNOTE.TXT 6.1): the three-word key schedule, the stream cipher, and the
// password check byte. It is weak but very common, including in malware
// packaging. Both decryption and encryption (for fixtures) are provided.
package zipcrypto

import (
	"hash/crc32"

	"github.com/rom/xcrypto"
)

// HeaderLen is the length of the per-entry encryption header.
const HeaderLen = 12

var crcTab = crc32.MakeTable(crc32.IEEE)

func crc32update(crc uint32, b byte) uint32 {
	return crcTab[(crc^uint32(b))&0xff] ^ (crc >> 8)
}

// Keys is the three-word PKWARE key state.
type Keys struct{ k0, k1, k2 uint32 }

// NewKeys initializes the key state from a password.
func NewKeys(password []byte) Keys {
	k := Keys{0x12345678, 0x23456789, 0x34567890}
	for _, b := range password {
		k.update(b)
	}
	return k
}

// Words returns the three internal key words (key0, key1, key2). It exposes a
// recovered state for reporting or for round-tripping through KeysFromWords.
func (k Keys) Words() (key0, key1, key2 uint32) { return k.k0, k.k1, k.k2 }

// KeysFromWords builds a Keys from the three internal words — e.g. the "X Y Z"
// an external engine such as bkcrack reports. The caller is responsible for
// validating them; the RecoverKeysWith offload path does so automatically.
func KeysFromWords(key0, key1, key2 uint32) Keys { return Keys{k0: key0, k1: key1, k2: key2} }

func (k *Keys) update(b byte) {
	k.k0 = crc32update(k.k0, b)
	k.k1 = k.k1 + (k.k0 & 0xff)
	k.k1 = k.k1*134775813 + 1
	k.k2 = crc32update(k.k2, byte(k.k1>>24))
}

func (k *Keys) streamByte() byte {
	temp := (k.k2 | 2) & 0xffff
	return byte((temp * (temp ^ 1)) >> 8)
}

// Decrypt decrypts data in place (the key update uses the recovered plaintext).
func (k *Keys) Decrypt(data []byte) {
	for i := range data {
		p := data[i] ^ k.streamByte()
		k.update(p)
		data[i] = p
	}
}

// Encrypt encrypts data in place.
func (k *Keys) Encrypt(data []byte) {
	for i := range data {
		p := data[i]
		data[i] = p ^ k.streamByte()
		k.update(p)
	}
}

// CheckByte returns the expected final header byte. When general-purpose bit 3
// is set (streaming), it is the high byte of the DOS mod-time; otherwise the
// high byte of the CRC-32.
func CheckByte(flags uint16, crc32val uint32, dosTime uint16) byte {
	if flags&0x8 != 0 {
		return byte(dosTime >> 8)
	}
	return byte(crc32val >> 24)
}

// HeaderOK runs the fast (1/256) header-byte check against expectCheck.
func HeaderOK(password, raw []byte, expectCheck byte) bool {
	if len(raw) < HeaderLen {
		return false
	}
	k := NewKeys(password)
	hdr := make([]byte, HeaderLen)
	copy(hdr, raw[:HeaderLen])
	k.Decrypt(hdr)
	return hdr[HeaderLen-1] == expectCheck
}

// Decrypt decrypts a raw entry (12-byte header + payload) with password and
// returns the still-compressed payload. It does not verify correctness beyond
// length; the caller confirms via CRC of the decompressed content.
func Decrypt(password, raw []byte) ([]byte, error) {
	if len(raw) < HeaderLen {
		return nil, xcrypto.ErrMalformed
	}
	buf := make([]byte, len(raw))
	copy(buf, raw)
	k := NewKeys(password)
	k.Decrypt(buf)
	return buf[HeaderLen:], nil
}

// EncryptRaw builds a raw ZipCrypto entry (fixtures): a 12-byte header whose
// last byte is checkByte, followed by compressed, all encrypted with password.
// randHeader must be 11 bytes of (ideally random) data.
func EncryptRaw(password, randHeader11 []byte, checkByte byte, compressed []byte) []byte {
	hdr := make([]byte, HeaderLen)
	copy(hdr, randHeader11)
	hdr[HeaderLen-1] = checkByte
	buf := append(hdr, compressed...)
	k := NewKeys(password)
	k.Encrypt(buf)
	return buf
}

// Challenge returns a reporting Challenge for a ZipCrypto entry.
func Challenge(uncompressedSize int64) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:            "zipcrypto",
		KDF:               xcrypto.KDFSpec{Algo: "none"},
		Cipher:            xcrypto.CipherSpec{Algo: "rc4-pkware"},
		DecryptedSizeHint: uncompressedSize,
	}
}
