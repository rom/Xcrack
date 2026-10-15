// Package ooxml implements the two ECMA-376 / MS-OFFCRYPTO encryption schemes
// used by password-protected Microsoft Office documents:
//
//   - Agile encryption (Office 2010+): an XML EncryptionInfo descriptor, an
//     iterated hash (configurable algorithm, spin count), AES-CBC, and a
//     self-contained verifier.
//   - Standard encryption (Office 2007): a binary EncryptionInfo, SHA-1 with
//     50000 iterations, AES-ECB.
//
// The package consumes the two byte blobs a Compound-File parser extracts -- the
// EncryptionInfo stream and the EncryptedPackage stream -- and knows nothing
// about the OLE/CFB container itself. Parsing + verification + decryption are
// here; encryption helpers (for fixtures) are in ooxml_encrypt.go.
package ooxml

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash"
	"strings"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/prim"
)

// Office agile block keys (MS-OFFCRYPTO 2.3.4.x).
var (
	blockVerifierHashInput = []byte{0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79}
	blockVerifierHashValue = []byte{0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e}
	blockEncryptedKeyValue = []byte{0x14, 0x6e, 0x0b, 0xe7, 0xab, 0xac, 0xd0, 0xd6}
)

const (
	agileSegment = 4096
	// maxSpinCount bounds the agile iterated-hash work factor against a crafted file.
	maxSpinCount = 50_000_000
)

// Info is a parsed EncryptionInfo. Use ParseEncryptionInfo to build one.
type Info struct {
	agile bool
	ag    agileInfo
	std   stdInfo
}

type agileInfo struct {
	keySalt   []byte
	keyBlock  int // keyData keyBits/8 (package secret key length)
	keyBlkSz  int // keyData blockSize
	keyHash   func() hash.Hash
	spinCount int
	pwSalt    []byte
	pwKeyLen  int // pwKey keyBits/8
	pwBlkSz   int
	pwHash    func() hash.Hash
	pwHashSz  int
	encVerIn  []byte
	encVerVal []byte
	encKeyVal []byte
}

type stdInfo struct {
	keyLen          int // bytes
	salt            []byte
	encVerifier     []byte
	encVerifierHash []byte
	iterations      int
}

// ParseEncryptionInfo parses an EncryptionInfo stream (agile or standard).
func ParseEncryptionInfo(b []byte) (*Info, error) {
	if len(b) < 8 {
		return nil, xcrypto.ErrMalformed
	}
	major := binary.LittleEndian.Uint16(b[0:2])
	minor := binary.LittleEndian.Uint16(b[2:4])
	switch {
	case major == 4 && minor == 4:
		return parseAgile(b[8:])
	case minor == 2 || minor == 3:
		return parseStandard(b)
	default:
		return nil, fmt.Errorf("%w: EncryptionInfo version %d.%d", xcrypto.ErrUnsupported, major, minor)
	}
}

// Scheme returns the scheme identifier.
func (i *Info) Scheme() string {
	if i.agile {
		return "ooxml-agile"
	}
	return "ooxml-standard"
}

// Challenge returns a reporting Challenge.
func (i *Info) Challenge() *xcrypto.Challenge {
	if i.agile {
		return &xcrypto.Challenge{
			Scheme: "ooxml-agile",
			KDF:    xcrypto.KDFSpec{Algo: "office-agile", Iterations: i.ag.spinCount, Salt: i.ag.pwSalt, KeyLen: i.ag.pwKeyLen},
			Cipher: xcrypto.CipherSpec{Algo: "aes-cbc", KeyBits: i.ag.pwKeyLen * 8},
		}
	}
	return &xcrypto.Challenge{
		Scheme: "ooxml-standard",
		KDF:    xcrypto.KDFSpec{Algo: "office-standard-sha1", Iterations: i.std.iterations, Salt: i.std.salt, KeyLen: i.std.keyLen},
		Cipher: xcrypto.CipherSpec{Algo: "aes-ecb", KeyBits: i.std.keyLen * 8},
	}
}

// --- agile ---

type agileXML struct {
	KeyData struct {
		BlockSize     int    `xml:"blockSize,attr"`
		KeyBits       int    `xml:"keyBits,attr"`
		HashAlgorithm string `xml:"hashAlgorithm,attr"`
		SaltValue     string `xml:"saltValue,attr"`
	} `xml:"keyData"`
	KeyEncryptors struct {
		KeyEncryptor []struct {
			EncryptedKey struct {
				SpinCount                  int    `xml:"spinCount,attr"`
				BlockSize                  int    `xml:"blockSize,attr"`
				KeyBits                    int    `xml:"keyBits,attr"`
				HashSize                   int    `xml:"hashSize,attr"`
				HashAlgorithm              string `xml:"hashAlgorithm,attr"`
				SaltValue                  string `xml:"saltValue,attr"`
				EncryptedVerifierHashInput string `xml:"encryptedVerifierHashInput,attr"`
				EncryptedVerifierHashValue string `xml:"encryptedVerifierHashValue,attr"`
				EncryptedKeyValue          string `xml:"encryptedKeyValue,attr"`
			} `xml:"encryptedKey"`
		} `xml:"keyEncryptor"`
	} `xml:"keyEncryptors"`
}

func parseAgile(xmlBytes []byte) (*Info, error) {
	var doc agileXML
	if err := xml.Unmarshal(xmlBytes, &doc); err != nil {
		return nil, fmt.Errorf("%w: agile XML: %v", xcrypto.ErrMalformed, err)
	}
	if len(doc.KeyEncryptors.KeyEncryptor) == 0 {
		return nil, fmt.Errorf("%w: no password key encryptor", xcrypto.ErrUnsupported)
	}
	ke := doc.KeyEncryptors.KeyEncryptor[0].EncryptedKey
	// Bound the attacker-controlled spin count so a crafted EncryptionInfo cannot
	// turn verification into a CPU-exhaustion DoS. Real files use ~100000.
	if ke.SpinCount < 0 || ke.SpinCount > maxSpinCount {
		return nil, fmt.Errorf("%w: implausible spinCount %d", xcrypto.ErrUnsupported, ke.SpinCount)
	}
	// Bound block sizes to sane AES values.
	if ke.BlockSize <= 0 || ke.BlockSize > 256 || doc.KeyData.BlockSize <= 0 || doc.KeyData.BlockSize > 256 {
		return nil, fmt.Errorf("%w: implausible block size", xcrypto.ErrMalformed)
	}
	keyHash, _, err := hashByName(doc.KeyData.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	pwHash, pwHashSz, err := hashByName(ke.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	b64 := func(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }
	keySalt, err1 := b64(doc.KeyData.SaltValue)
	pwSalt, err2 := b64(ke.SaltValue)
	encVerIn, err3 := b64(ke.EncryptedVerifierHashInput)
	encVerVal, err4 := b64(ke.EncryptedVerifierHashValue)
	encKeyVal, err5 := b64(ke.EncryptedKeyValue)
	for _, e := range []error{err1, err2, err3, err4, err5} {
		if e != nil {
			return nil, fmt.Errorf("%w: base64: %v", xcrypto.ErrMalformed, e)
		}
	}
	if ke.HashSize > 0 {
		pwHashSz = ke.HashSize
	}
	return &Info{agile: true, ag: agileInfo{
		keySalt:   keySalt,
		keyBlock:  doc.KeyData.KeyBits / 8,
		keyBlkSz:  doc.KeyData.BlockSize,
		keyHash:   keyHash,
		spinCount: ke.SpinCount,
		pwSalt:    pwSalt,
		pwKeyLen:  ke.KeyBits / 8,
		pwBlkSz:   ke.BlockSize,
		pwHash:    pwHash,
		pwHashSz:  pwHashSz,
		encVerIn:  encVerIn,
		encVerVal: encVerVal,
		encKeyVal: encKeyVal,
	}}, nil
}

func (i *Info) verifyAgile(password []byte) (bool, error) {
	a := i.ag
	pw := prim.UTF16LE(password)
	hfinal := prim.OfficeAgileHash(a.pwHash, a.pwSalt, pw, a.spinCount)
	keyVI := prim.OfficeAgileKey(a.pwHash, hfinal, blockVerifierHashInput, a.pwKeyLen)
	keyVV := prim.OfficeAgileKey(a.pwHash, hfinal, blockVerifierHashValue, a.pwKeyLen)
	iv := prim.OfficeAgileIV(a.pwHash, a.pwSalt, nil, a.pwBlkSz)
	vhIn, err := prim.CBCDecrypt(keyVI, iv, a.encVerIn)
	if err != nil {
		return false, err
	}
	vhVal, err := prim.CBCDecrypt(keyVV, iv, a.encVerVal)
	if err != nil {
		return false, err
	}
	h := a.pwHash()
	h.Write(vhIn)
	digest := h.Sum(nil)
	n := len(digest)
	if n > len(vhVal) {
		return false, nil
	}
	return prim.ConstantTimeEqual(digest, vhVal[:n]), nil
}

func (i *Info) deriveSecretAgile(password []byte) ([]byte, error) {
	a := i.ag
	pw := prim.UTF16LE(password)
	hfinal := prim.OfficeAgileHash(a.pwHash, a.pwSalt, pw, a.spinCount)
	keyK := prim.OfficeAgileKey(a.pwHash, hfinal, blockEncryptedKeyValue, a.pwKeyLen)
	ivK := prim.OfficeAgileIV(a.pwHash, a.pwSalt, nil, a.pwBlkSz)
	secret, err := prim.CBCDecrypt(keyK, ivK, a.encKeyVal)
	if err != nil {
		return nil, err
	}
	if len(secret) < a.keyBlock {
		return nil, xcrypto.ErrMalformed
	}
	return secret[:a.keyBlock], nil
}

func (i *Info) decryptAgileWithKey(secret, encryptedPackage []byte) ([]byte, error) {
	a := i.ag
	if len(encryptedPackage) < 8 {
		return nil, xcrypto.ErrMalformed
	}
	size := int64(binary.LittleEndian.Uint64(encryptedPackage[:8]))
	data := encryptedPackage[8:]
	out := make([]byte, 0, len(data))
	var ib [4]byte
	for seg := 0; seg*agileSegment < len(data); seg++ {
		off := seg * agileSegment
		end := off + agileSegment
		if end > len(data) {
			end = len(data)
		}
		chunk := data[off:end]
		if len(chunk)%i.ag.keyBlkSz != 0 {
			return nil, xcrypto.ErrMalformed
		}
		binary.LittleEndian.PutUint32(ib[:], uint32(seg))
		iv := prim.OfficeAgileIV(a.keyHash, a.keySalt, ib[:], a.keyBlkSz)
		dec, err := prim.CBCDecrypt(secret, iv, chunk)
		if err != nil {
			return nil, err
		}
		out = append(out, dec...)
	}
	if size < 0 || size > int64(len(out)) {
		return nil, xcrypto.ErrMalformed
	}
	return out[:size], nil
}

// --- standard ---

func parseStandard(b []byte) (*Info, error) {
	if len(b) < 12 {
		return nil, xcrypto.ErrMalformed
	}
	headerSize := int(binary.LittleEndian.Uint32(b[8:12]))
	if headerSize < 32 || 12+headerSize > len(b) {
		return nil, xcrypto.ErrMalformed
	}
	hdr := b[12 : 12+headerSize]
	algID := binary.LittleEndian.Uint32(hdr[8:12])
	keyBits := int(binary.LittleEndian.Uint32(hdr[20:24]))
	keyLen := keyBits / 8
	switch algID {
	case 0x6610:
		keyLen = 16
	case 0x6611:
		keyLen = 24
	case 0x6612:
		keyLen = 32
	case 0:
		// keyBits from header
	default:
		return nil, fmt.Errorf("%w: standard algID 0x%x (only AES supported)", xcrypto.ErrUnsupported, algID)
	}
	if keyLen == 0 {
		return nil, fmt.Errorf("%w: standard key size unknown", xcrypto.ErrUnsupported)
	}
	v := b[12+headerSize:]
	if len(v) < 8 {
		return nil, xcrypto.ErrMalformed
	}
	saltSize := int(binary.LittleEndian.Uint32(v[0:4]))
	if saltSize != 16 || len(v) < 4+saltSize+16+4 {
		return nil, xcrypto.ErrMalformed
	}
	salt := v[4 : 4+saltSize]
	encVerifier := v[4+saltSize : 4+saltSize+16]
	rest := v[4+saltSize+16:]
	verifierHashSize := int(binary.LittleEndian.Uint32(rest[0:4]))
	encVerHash := rest[4:]
	if verifierHashSize > len(encVerHash) {
		verifierHashSize = len(encVerHash)
	}
	// encrypted verifier hash is padded to a block multiple (32 bytes for SHA1)
	if len(encVerHash) < 20 {
		return nil, xcrypto.ErrMalformed
	}
	return &Info{std: stdInfo{
		keyLen:          keyLen,
		salt:            append([]byte(nil), salt...),
		encVerifier:     append([]byte(nil), encVerifier...),
		encVerifierHash: append([]byte(nil), encVerHash...),
		iterations:      50000,
	}}, nil
}

func (i *Info) verifyStandard(password []byte) (bool, error) {
	s := i.std
	key := prim.OfficeStandardKey(sha1.New, s.salt, prim.UTF16LE(password), s.iterations, s.keyLen)
	verifier, err := prim.ECBDecrypt(key, s.encVerifier)
	if err != nil {
		return false, err
	}
	hashLen := (len(s.encVerifierHash) / 16) * 16
	vhash, err := prim.ECBDecrypt(key, s.encVerifierHash[:hashLen])
	if err != nil {
		return false, err
	}
	h := sha1.New()
	h.Write(verifier)
	digest := h.Sum(nil)
	if len(vhash) < len(digest) {
		return false, nil
	}
	return prim.ConstantTimeEqual(digest, vhash[:len(digest)]), nil
}

func (i *Info) deriveSecretStandard(password []byte) ([]byte, error) {
	s := i.std
	return prim.OfficeStandardKey(sha1.New, s.salt, prim.UTF16LE(password), s.iterations, s.keyLen), nil
}

func (i *Info) decryptStandardWithKey(key, encryptedPackage []byte) ([]byte, error) {
	if len(encryptedPackage) < 8 {
		return nil, xcrypto.ErrMalformed
	}
	size := int64(binary.LittleEndian.Uint64(encryptedPackage[:8]))
	data := encryptedPackage[8:]
	aligned := (len(data) / 16) * 16
	plain, err := prim.ECBDecrypt(key, data[:aligned])
	if err != nil {
		return nil, err
	}
	if size < 0 || size > int64(len(plain)) {
		return nil, xcrypto.ErrMalformed
	}
	return plain[:size], nil
}

// --- public verify/decrypt dispatch ---

// Verify authoritatively checks a password against the EncryptionInfo verifier.
func (i *Info) Verify(password []byte) (bool, error) {
	if i.agile {
		return i.verifyAgile(password)
	}
	return i.verifyStandard(password)
}

// DeriveSecretKey derives the secret key that decrypts the package: for agile
// encryption the decrypted encryptedKeyValue, for standard encryption the AES
// key. Splitting this out lets a caller verify once and decrypt without redoing
// the whole key-derivation twice.
func (i *Info) DeriveSecretKey(password []byte) ([]byte, error) {
	if i.agile {
		return i.deriveSecretAgile(password)
	}
	return i.deriveSecretStandard(password)
}

// DecryptPackageWithKey decrypts the EncryptedPackage stream using a secret key
// from DeriveSecretKey, returning the inner OOXML (a ZIP) bytes.
func (i *Info) DecryptPackageWithKey(secretKey, encryptedPackage []byte) ([]byte, error) {
	if i.agile {
		return i.decryptAgileWithKey(secretKey, encryptedPackage)
	}
	return i.decryptStandardWithKey(secretKey, encryptedPackage)
}

// DecryptPackage decrypts the EncryptedPackage stream with password, returning
// the inner OOXML (a ZIP) bytes.
func (i *Info) DecryptPackage(password, encryptedPackage []byte) ([]byte, error) {
	secret, err := i.DeriveSecretKey(password)
	if err != nil {
		return nil, err
	}
	return i.DecryptPackageWithKey(secret, encryptedPackage)
}

func hashByName(name string) (func() hash.Hash, int, error) {
	switch strings.ToLower(strings.ReplaceAll(name, "-", "")) {
	case "sha512":
		return sha512.New, 64, nil
	case "sha384":
		return sha512.New384, 48, nil
	case "sha256":
		return sha256.New, 32, nil
	case "sha1", "":
		return sha1.New, 20, nil
	}
	return nil, 0, fmt.Errorf("%w: hash %q", xcrypto.ErrUnsupported, name)
}
