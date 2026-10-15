package ooxml

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"github.com/rom/xcrypto/prim"
)

// These helpers build encrypted Office streams for tests and tooling. They
// mirror the decryption paths above. Agile uses SHA-512 / AES-256-CBC; standard
// uses SHA-1 / AES-ECB.

func randN(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func padBlock(b []byte, bs int) []byte {
	if len(b)%bs == 0 {
		return b
	}
	out := make([]byte, len(b)+(bs-len(b)%bs))
	copy(out, b)
	return out
}

// EncryptAgile encrypts pkg (the inner OOXML zip bytes) with password using
// agile encryption, returning the EncryptionInfo and EncryptedPackage streams.
// spinCount should be small in tests (the real default is 100000).
func EncryptAgile(password, pkg []byte, spinCount int) (encInfo, encPkg []byte, err error) {
	const keyBits, blockSize = 256, 16
	keyLen := keyBits / 8
	newHash := sha512.New
	keySalt, pwSalt := randN(blockSize), randN(blockSize)
	pw := prim.UTF16LE(password)

	hfinal := prim.OfficeAgileHash(newHash, pwSalt, pw, spinCount)
	keyVI := prim.OfficeAgileKey(newHash, hfinal, blockVerifierHashInput, keyLen)
	keyVV := prim.OfficeAgileKey(newHash, hfinal, blockVerifierHashValue, keyLen)
	keyK := prim.OfficeAgileKey(newHash, hfinal, blockEncryptedKeyValue, keyLen)
	iv := prim.OfficeAgileIV(newHash, pwSalt, nil, blockSize)

	verIn := randN(blockSize)
	h := newHash()
	h.Write(verIn)
	verVal := h.Sum(nil)

	encVerIn, err := prim.CBCEncrypt(keyVI, iv, verIn)
	if err != nil {
		return nil, nil, err
	}
	encVerVal, err := prim.CBCEncrypt(keyVV, iv, padBlock(verVal, blockSize))
	if err != nil {
		return nil, nil, err
	}
	secret := randN(keyLen)
	encKeyVal, err := prim.CBCEncrypt(keyK, iv, secret)
	if err != nil {
		return nil, nil, err
	}

	// EncryptedPackage
	padded := padBlock(pkg, blockSize)
	out := make([]byte, 8, 8+len(padded))
	binary.LittleEndian.PutUint64(out[:8], uint64(len(pkg)))
	var ib [4]byte
	for seg := 0; seg*agileSegment < len(padded); seg++ {
		off := seg * agileSegment
		end := off + agileSegment
		if end > len(padded) {
			end = len(padded)
		}
		binary.LittleEndian.PutUint32(ib[:], uint32(seg))
		segIV := prim.OfficeAgileIV(newHash, keySalt, ib[:], blockSize)
		enc, err := prim.CBCEncrypt(secret, segIV, padded[off:end])
		if err != nil {
			return nil, nil, err
		}
		out = append(out, enc...)
	}

	b64 := base64.StdEncoding.EncodeToString
	xmlDoc := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`+
		`<encryption xmlns="http://schemas.microsoft.com/office/2006/encryption" `+
		`xmlns:p="http://schemas.microsoft.com/office/2006/keyEncryptor/password">`+
		`<keyData saltSize="16" blockSize="16" keyBits="256" hashSize="64" `+
		`cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="%s"/>`+
		`<keyEncryptors><keyEncryptor uri="http://schemas.microsoft.com/office/2006/keyEncryptor/password">`+
		`<p:encryptedKey spinCount="%d" saltSize="16" blockSize="16" keyBits="256" hashSize="64" `+
		`cipherAlgorithm="AES" cipherChaining="ChainingModeCBC" hashAlgorithm="SHA512" saltValue="%s" `+
		`encryptedVerifierHashInput="%s" encryptedVerifierHashValue="%s" encryptedKeyValue="%s"/>`+
		`</keyEncryptor></keyEncryptors></encryption>`,
		b64(keySalt), spinCount, b64(pwSalt), b64(encVerIn), b64(encVerVal), b64(encKeyVal))

	info := append([]byte{0x04, 0x00, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00}, []byte(xmlDoc)...)
	return info, out, nil
}

// EncryptStandard encrypts pkg with password using standard (Office 2007)
// encryption with the given AES key length (16/24/32 bytes).
func EncryptStandard(password, pkg []byte, keyLen int) (encInfo, encPkg []byte, err error) {
	salt := randN(16)
	key := prim.OfficeStandardKey(sha1.New, salt, prim.UTF16LE(password), 50000, keyLen)

	verifier := randN(16)
	h := sha1.New()
	h.Write(verifier)
	verHash := h.Sum(nil) // 20 bytes
	encVerifier, err := prim.ECBEncrypt(key, verifier)
	if err != nil {
		return nil, nil, err
	}
	encVerHash, err := prim.ECBEncrypt(key, padBlock(verHash, 16)) // 32 bytes
	if err != nil {
		return nil, nil, err
	}

	// EncryptedPackage
	padded := padBlock(pkg, 16)
	encPkgData, err := prim.ECBEncrypt(key, padded)
	if err != nil {
		return nil, nil, err
	}
	encPkg = make([]byte, 8, 8+len(encPkgData))
	binary.LittleEndian.PutUint64(encPkg[:8], uint64(len(pkg)))
	encPkg = append(encPkg, encPkgData...)

	algID := map[int]uint32{16: 0x6610, 24: 0x6611, 32: 0x6612}[keyLen]
	cspName := prim.UTF16LE([]byte("Microsoft Enhanced RSA and AES Cryptographic Provider"))
	cspName = append(cspName, 0, 0)

	header := make([]byte, 32)
	binary.LittleEndian.PutUint32(header[0:4], 0x24)               // flags: fCryptoAPI | fAES
	binary.LittleEndian.PutUint32(header[8:12], algID)             // algID
	binary.LittleEndian.PutUint32(header[12:16], 0x8004)           // algIDHash = SHA1
	binary.LittleEndian.PutUint32(header[16:20], uint32(keyLen*8)) // keySize bits
	binary.LittleEndian.PutUint32(header[20:24], 0x18)             // providerType = AES
	header = append(header, cspName...)

	verifierBlock := make([]byte, 0, 4+16+16+4+len(encVerHash))
	verifierBlock = binary.LittleEndian.AppendUint32(verifierBlock, 16) // saltSize
	verifierBlock = append(verifierBlock, salt...)
	verifierBlock = append(verifierBlock, encVerifier...)
	verifierBlock = binary.LittleEndian.AppendUint32(verifierBlock, 20) // verifierHashSize
	verifierBlock = append(verifierBlock, encVerHash...)

	info := make([]byte, 0, 12+len(header)+len(verifierBlock))
	info = binary.LittleEndian.AppendUint16(info, 3)    // major
	info = binary.LittleEndian.AppendUint16(info, 2)    // minor
	info = binary.LittleEndian.AppendUint32(info, 0x24) // flags
	info = binary.LittleEndian.AppendUint32(info, uint32(len(header)))
	info = append(info, header...)
	info = append(info, verifierBlock...)
	return info, encPkg, nil
}
