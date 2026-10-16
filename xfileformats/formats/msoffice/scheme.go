package msoffice

import (
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/officebinary"
)

// encInfo holds the legacy encryption parameters parsed from a document, shared
// by every encrypted stream of that document (one password unlocks all).
type encInfo struct {
	kind            string // "rc4", "rc4-cryptoapi", or "xor"
	salt            []byte
	keyBits         int    // RC4 CryptoAPI key length in bits
	encVerifier     []byte // RC4 families
	encVerifierHash []byte // RC4 families
	xorVerifier     uint16 // XOR obfuscation
}

func (ei *encInfo) verify(pw []byte) (bool, error) {
	switch ei.kind {
	case "rc4-cryptoapi":
		return officebinary.VerifyCryptoAPI(pw, ei.salt, ei.keyBits, ei.encVerifier, ei.encVerifierHash)
	case "rc4":
		return officebinary.VerifyRC4(pw, ei.salt, ei.encVerifier, ei.encVerifierHash)
	case "xor":
		return officebinary.VerifyXOR(pw, ei.xorVerifier), nil
	}
	return false, nil
}

func (ei *encInfo) challenge() *xcrypto.Challenge {
	switch ei.kind {
	case "rc4-cryptoapi":
		return officebinary.ChallengeCryptoAPI(ei.salt, ei.keyBits, ei.encVerifier, ei.encVerifierHash)
	case "rc4":
		return officebinary.ChallengeRC4(ei.salt, ei.encVerifier, ei.encVerifierHash)
	case "xor":
		return officebinary.ChallengeXOR(ei.xorVerifier)
	}
	return nil
}

// decryptBlocks decrypts a whole stream with the RC4 family (block-rekeyed).
func (ei *encInfo) decryptBlocks(pw, data []byte, blockSize int, startBlock uint32) ([]byte, error) {
	switch ei.kind {
	case "rc4-cryptoapi":
		return officebinary.DecryptCryptoAPI(pw, ei.salt, ei.keyBits, data, blockSize, startBlock)
	case "rc4":
		return officebinary.DecryptRC4(pw, ei.salt, data, blockSize)
	}
	return nil, xcrypto.ErrUnsupported
}

func errWrongPassword(err error) error {
	if err != nil {
		return err
	}
	return xcrypto.ErrWrongPassword
}

// parseRC4Header parses an Office 97/2000 RC4 EncryptionHeader (the bytes after
// the 4-byte version info): salt(16) + encryptedVerifier(16) +
// encryptedVerifierHash(16). [MS-OFFCRYPTO] 2.3.6.
func parseRC4Header(b []byte, ei *encInfo) bool {
	if len(b) < 48 {
		return false
	}
	ei.salt = append([]byte{}, b[0:16]...)
	ei.encVerifier = append([]byte{}, b[16:32]...)
	ei.encVerifierHash = append([]byte{}, b[32:48]...)
	return true
}

// parseCryptoAPIHeader parses an RC4 CryptoAPI EncryptionInfo (the bytes after
// the 4-byte version info): EncryptionHeaderFlags(4) + EncryptionHeaderSize(4) +
// EncryptionHeader + EncryptionVerifier. [MS-OFFCRYPTO] 2.3.4.5 / 2.3.5.1.
func parseCryptoAPIHeader(b []byte, ei *encInfo) bool {
	if len(b) < 8 {
		return false
	}
	headerSize := int(u32(b, 4))
	off := 8
	if headerSize < 0 || off+headerSize > len(b) {
		return false
	}
	header := b[off : off+headerSize]
	off += headerSize
	// EncryptionHeader: Flags(4) SizeExtra(4) AlgID(4) AlgIDHash(4) KeySize(4) ...
	if len(header) < 20 {
		return false
	}
	keyBits := int(u32(header, 16))
	if keyBits == 0 {
		keyBits = 0x28 // default 40-bit when unspecified
	}
	// EncryptionVerifier: SaltSize(4) Salt(16) EncryptedVerifier(16)
	// VerifierHashSize(4) EncryptedVerifierHash(20 for RC4/SHA-1).
	v := b[off:]
	if len(v) < 4+16+16+4+20 {
		return false
	}
	ei.keyBits = keyBits
	ei.salt = append([]byte{}, v[4:20]...)
	ei.encVerifier = append([]byte{}, v[20:36]...)
	ei.encVerifierHash = append([]byte{}, v[40:60]...)
	return true
}

// parseVersionedRC4 reads the 4-byte EncryptionVersionInfo at the start of
// stream and fills ei for the RC4 family. stream is the full encryption-info
// blob (version + header). Returns false if the version is not a supported RC4
// variant.
func parseVersionedRC4(stream []byte, ei *encInfo) bool {
	if len(stream) < 4 {
		return false
	}
	vMajor := u16(stream, 0)
	vMinor := u16(stream, 2)
	switch {
	case vMajor == 1 && vMinor == 1:
		ei.kind = "rc4"
		return parseRC4Header(stream[4:], ei)
	case (vMajor == 2 || vMajor == 3 || vMajor == 4) && vMinor == 2:
		ei.kind = "rc4-cryptoapi"
		return parseCryptoAPIHeader(stream[4:], ei)
	}
	return false
}
