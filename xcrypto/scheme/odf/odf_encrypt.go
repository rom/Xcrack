package odf

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"

	"github.com/rom/xcrypto/prim"
)

// EncryptEntry builds a raw encrypted ODF entry (AES-256-CBC) for content,
// returning the ciphertext and the manifest parameters. Used for fixtures.
func EncryptEntry(password, content []byte, iterations int) ([]byte, EntryParams, error) {
	var cb bytes.Buffer
	fw, _ := flate.NewWriter(&cb, flate.DefaultCompression)
	fw.Write(content)
	fw.Close()
	compressed := cb.Bytes()

	padded := compressed
	if n := len(padded) % 16; n != 0 {
		padded = append(append([]byte(nil), padded...), make([]byte, 16-n)...)
	}

	salt := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(salt)
	rand.Read(iv)

	p := EntryParams{
		Algorithm:        "http://www.w3.org/2001/04/xmlenc#aes256-cbc",
		IV:               iv,
		Salt:             salt,
		Iterations:       iterations,
		KeySize:          32,
		StartKeyHash:     "SHA256",
		ChecksumType:     "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0#sha256-1k",
		UncompressedSize: int64(len(content)),
	}
	head := padded
	if len(head) > 1024 {
		head = head[:1024]
	}
	cs := sha256.Sum256(head)
	p.Checksum = cs[:]

	key, err := DeriveKey(password, p)
	if err != nil {
		return nil, p, err
	}
	ct, err := prim.CBCEncrypt(key, iv, padded)
	if err != nil {
		return nil, p, err
	}
	return ct, p, nil
}

// EncryptEntryGCM builds a raw encrypted ODF entry using the ODF 1.3 authenticated
// AES-256-GCM variant: the returned bytes are the ciphertext with the 128-bit GCM
// tag appended (nonce = the 12-byte IV in the returned params). No 1K checksum is
// produced; the GCM tag is the integrity/verification value. Used for fixtures.
func EncryptEntryGCM(password, content []byte, iterations int) ([]byte, EntryParams, error) {
	var cb bytes.Buffer
	fw, _ := flate.NewWriter(&cb, flate.DefaultCompression)
	fw.Write(content)
	fw.Close()
	compressed := cb.Bytes()

	salt := make([]byte, 16)
	iv := make([]byte, 12) // GCM 96-bit nonce
	rand.Read(salt)
	rand.Read(iv)

	p := EntryParams{
		Algorithm:        "http://www.w3.org/2009/xmlenc11#aes256-gcm",
		IV:               iv,
		Salt:             salt,
		Iterations:       iterations,
		KeySize:          32,
		StartKeyHash:     "SHA256",
		UncompressedSize: int64(len(content)),
	}
	key, err := DeriveKey(password, p)
	if err != nil {
		return nil, p, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, p, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, len(iv))
	if err != nil {
		return nil, p, err
	}
	return aead.Seal(nil, iv, compressed, nil), p, nil
}
