// Package privkey detects and cracks passphrase-protected private keys in the
// two common PEM encodings produced by OpenSSL:
//
//   - legacy ("traditional") PEM — "BEGIN RSA/EC/DSA PRIVATE KEY" with
//     "Proc-Type: 4,ENCRYPTED" and a "DEK-Info" header (EVP_BytesToKey + a block
//     cipher). Decryption uses the standard library.
//   - PKCS#8 — "BEGIN ENCRYPTED PRIVATE KEY" with a PBES2 scheme (PBKDF2 or
//     scrypt, then AES-CBC). Parsed and decrypted here.
//
// Only the passphrase is attacked. A candidate is confirmed by decrypting and
// checking that the result is a well-formed private key (valid padding + parses),
// so a false positive is ~2^-32. Delegated primitives come from the standard
// library and the vetted golang.org/x/crypto.
package privkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"hash"

	"github.com/rom/xcrypto"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

// ErrNotKey means the input is not a PEM private key.
var ErrNotKey = errors.New("privkey: not a PEM private key")

// ErrNotEncrypted means the key is present but not passphrase-protected.
var ErrNotEncrypted = errors.New("privkey: key is not encrypted")

// ErrUnsupported means the key is encrypted with a scheme not handled here.
var ErrUnsupported = errors.New("privkey: unsupported encryption scheme")

// Bounds on the attacker-controlled PBES2 KDF cost parameters, so a crafted
// PKCS#8 header cannot turn verification into an unbounded CPU hang (PBKDF2
// iterations) or a multi-GiB allocation (scrypt, whose working set is
// ~128*N*r bytes). Real keys stay far below these.
const (
	maxPBKDF2Iter       = 1 << 24
	maxScryptN          = 1 << 20
	maxScryptR          = 64
	maxScryptP          = 16
	maxScryptMem  int64 = 1 << 30 // 1 GiB
)

// OIDs for PBES2 / PBKDF2 / scrypt / ciphers / PRFs.
var (
	oidPBES2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidScrypt     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11591, 4, 11}
	oidHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

type algorithmIdentifier struct {
	Algorithm asn1.ObjectIdentifier
	Params    asn1.RawValue `asn1:"optional"`
}

type encryptedPrivateKeyInfo struct {
	Algo          algorithmIdentifier
	EncryptedData []byte
}

type pbes2Params struct {
	KDF       algorithmIdentifier
	EncScheme algorithmIdentifier
}

type pbkdf2Params struct {
	Salt      []byte
	Iter      int
	KeyLength int                 `asn1:"optional"`
	PRF       algorithmIdentifier `asn1:"optional"`
}

type scryptParams struct {
	Salt      []byte
	N, R, P   int
	KeyLength int `asn1:"optional"`
}

// Mode distinguishes the two PEM encodings.
type Mode int

const (
	ModeLegacy Mode = iota // DEK-Info traditional PEM
	ModePKCS8              // PBES2
)

// Info describes a parsed encrypted private key.
type Info struct {
	Mode   Mode
	PEM    []byte // original PEM (legacy decryption needs the pem.Block)
	Scheme string // human-readable, for reporting
	Salt   []byte
	Iter   int
}

// Parse decodes the PEM and classifies the key. ErrNotEncrypted for a plain key.
func Parse(data []byte) (*Info, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, ErrNotKey
	}
	switch {
	case block.Type == "ENCRYPTED PRIVATE KEY":
		epki := encryptedPrivateKeyInfo{}
		if _, err := asn1.Unmarshal(block.Bytes, &epki); err != nil {
			return nil, ErrNotKey
		}
		if !epki.Algo.Algorithm.Equal(oidPBES2) {
			return nil, ErrUnsupported
		}
		d, _, _, _, salt, iter, scheme, err := parsePBES2(epki)
		_ = d
		if err != nil {
			return nil, err
		}
		return &Info{Mode: ModePKCS8, PEM: dup(data), Scheme: scheme, Salt: salt, Iter: iter}, nil
	case isPrivateKeyType(block.Type):
		if _, ok := block.Headers["DEK-Info"]; !ok {
			return nil, ErrNotEncrypted
		}
		return &Info{Mode: ModeLegacy, PEM: dup(data), Scheme: "openssl-legacy/" + block.Headers["DEK-Info"]}, nil
	default:
		return nil, ErrNotKey
	}
}

func isPrivateKeyType(t string) bool {
	switch t {
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY", "PRIVATE KEY", "OPENSSH PRIVATE KEY":
		return t != "OPENSSH PRIVATE KEY" // OpenSSH handled by the sshkey package
	}
	return false
}

// Verify reports whether passphrase decrypts the key to a well-formed private key.
func Verify(pemBytes, passphrase []byte) (bool, error) {
	der, err := decryptKey(pemBytes, passphrase)
	if err != nil {
		return false, nil
	}
	return looksLikeKey(der), nil
}

// Decrypt returns the decrypted key as an unencrypted PKCS#8 PEM (or, when it is
// not PKCS#8-parseable but is a valid PKCS#1/SEC1 key, the raw DER PEM).
func Decrypt(pemBytes, passphrase []byte) ([]byte, error) {
	der, err := decryptKey(pemBytes, passphrase)
	if err != nil {
		return nil, err
	}
	if !looksLikeKey(der) {
		return nil, errors.New("privkey: wrong passphrase")
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if der2, err := x509.MarshalPKCS8PrivateKey(key); err == nil {
			return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der2}), nil
		}
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// decryptKey returns the decrypted DER bytes for either encoding.
func decryptKey(pemBytes, passphrase []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrNotKey
	}
	if block.Type == "ENCRYPTED PRIVATE KEY" {
		epki := encryptedPrivateKeyInfo{}
		if _, err := asn1.Unmarshal(block.Bytes, &epki); err != nil {
			return nil, err
		}
		key, iv, blkSize, enc, _, _, _, err := parsePBES2(epki)
		if err != nil {
			return nil, err
		}
		dk := pbdkKey(key, passphrase)
		return aesCBCUnpad(dk, iv, enc, blkSize)
	}
	// legacy DEK-Info PEM
	if _, ok := block.Headers["DEK-Info"]; !ok {
		return nil, ErrNotEncrypted
	}
	return x509.DecryptPEMBlock(block, passphrase) //nolint:staticcheck // legacy format by design
}

// pbdk holds a key-derivation closure captured from PBES2 params.
type pbdk func(passphrase []byte) []byte

func pbdkKey(d pbdk, passphrase []byte) []byte { return d(passphrase) }

// parsePBES2 extracts the KDF closure, IV, cipher block size, ciphertext, and
// (for reporting) salt/iter/scheme from a PBES2 EncryptedPrivateKeyInfo.
func parsePBES2(epki encryptedPrivateKeyInfo) (d pbdk, iv []byte, blkSize int, enc, salt []byte, iter int, scheme string, err error) {
	var p pbes2Params
	if _, err = asn1.Unmarshal(epki.Algo.Params.FullBytes, &p); err != nil {
		return
	}
	// Encryption scheme: AES-CBC with the IV in its params.
	keyLen, ok := aesKeyLen(p.EncScheme.Algorithm)
	if !ok {
		err = ErrUnsupported
		return
	}
	if _, err = asn1.Unmarshal(p.EncScheme.Params.FullBytes, &iv); err != nil {
		return
	}
	blkSize = aes.BlockSize
	enc = epki.EncryptedData

	switch {
	case p.KDF.Algorithm.Equal(oidPBKDF2):
		var kp pbkdf2Params
		if _, err = asn1.Unmarshal(p.KDF.Params.FullBytes, &kp); err != nil {
			return
		}
		if kp.Iter < 1 || kp.Iter > maxPBKDF2Iter {
			err = ErrUnsupported // implausible PBKDF2 cost: refuse rather than hang
			return
		}
		h := prfHash(kp.PRF.Algorithm)
		salt, iter = kp.Salt, kp.Iter
		scheme = "pbes2-pbkdf2-aes" + bits(keyLen)
		d = func(pw []byte) []byte { return pbkdf2.Key(pw, kp.Salt, kp.Iter, keyLen, h) }
	case p.KDF.Algorithm.Equal(oidScrypt):
		var sp scryptParams
		if _, err = asn1.Unmarshal(p.KDF.Params.FullBytes, &sp); err != nil {
			return
		}
		if sp.N < 2 || sp.N > maxScryptN || sp.N&(sp.N-1) != 0 || // N a power of two > 1
			sp.R < 1 || sp.R > maxScryptR || sp.P < 1 || sp.P > maxScryptP ||
			int64(128)*int64(sp.N)*int64(sp.R) > maxScryptMem { // bound the working set
			err = ErrUnsupported
			return
		}
		salt, iter = sp.Salt, sp.N
		scheme = "pbes2-scrypt-aes" + bits(keyLen)
		N, r, pp := sp.N, sp.R, sp.P
		d = func(pw []byte) []byte {
			k, derr := scrypt.Key(pw, sp.Salt, N, r, pp, keyLen)
			if derr != nil {
				return nil
			}
			return k
		}
	default:
		err = ErrUnsupported
	}
	return
}

func aesKeyLen(oid asn1.ObjectIdentifier) (int, bool) {
	switch {
	case oid.Equal(oidAES128CBC):
		return 16, true
	case oid.Equal(oidAES192CBC):
		return 24, true
	case oid.Equal(oidAES256CBC):
		return 32, true
	}
	return 0, false
}

func prfHash(oid asn1.ObjectIdentifier) func() hash.Hash {
	switch {
	case oid.Equal(oidHMACSHA256):
		return sha256.New
	case oid.Equal(oidHMACSHA512):
		return sha512.New
	default:
		return sha1.New // PBKDF2 default
	}
}

// aesCBCUnpad decrypts AES-CBC and removes PKCS#7 padding, returning an error on
// invalid padding (a cheap, reliable wrong-password signal).
func aesCBCUnpad(key, iv, ct []byte, blkSize int) ([]byte, error) {
	if key == nil || len(ct) == 0 || len(ct)%blkSize != 0 || len(iv) != blkSize {
		return nil, errors.New("privkey: bad ciphertext")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, ct)
	pad := int(out[len(out)-1])
	if pad == 0 || pad > blkSize || pad > len(out) {
		return nil, errors.New("privkey: bad padding")
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, errors.New("privkey: bad padding")
		}
	}
	return out[:len(out)-pad], nil
}

// looksLikeKey reports whether der parses as a private key in any standard form.
func looksLikeKey(der []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return true
	}
	if _, err := x509.ParseECPrivateKey(der); err == nil {
		return true
	}
	return false
}

// Challenge builds a reporting Challenge for a parsed key.
func Challenge(info *Info) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme: "privkey",
		KDF:    xcrypto.KDFSpec{Algo: info.Scheme, Iterations: info.Iter, Salt: info.Salt},
		Extra:  map[string][]byte{"pem": info.PEM},
	}
}

func dup(b []byte) []byte { return append([]byte(nil), b...) }

func bits(keyLen int) string {
	switch keyLen {
	case 16:
		return "128"
	case 24:
		return "192"
	case 32:
		return "256"
	}
	return "?"
}
