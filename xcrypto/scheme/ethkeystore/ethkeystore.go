// Package ethkeystore implements passphrase verification for Ethereum keystore
// files — the Web3 Secret Storage Definition, version 3, as written by geth,
// MetaMask, MyEtherWallet and most wallets (the "UTC--..." / keystore JSON).
//
// The passphrase derives a 32-byte key via scrypt or PBKDF2-HMAC-SHA256, and
// the file stores a MAC = Keccak-256( derivedKey[16:32] || ciphertext ). That
// MAC is a strong verifier: a wrong passphrase fails it with cryptographic
// certainty (no padding-oracle guesswork), and it needs no decryption of the
// private key. Only verification is implemented; the wallet's private key is
// the deliverable the passphrase unlocks, not reconstructed here.
package ethkeystore

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/sha3"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/prim"
)

// KDF identifies the key-derivation function a keystore uses.
type KDF int

const (
	KDFScrypt KDF = iota
	KDFPBKDF2
)

// Params are the fields a keystore's "crypto" object carries that are needed to
// verify a passphrase.
type Params struct {
	KDF        KDF
	Salt       []byte
	DKLen      int
	Ciphertext []byte
	MAC        []byte // the stored Keccak-256 MAC

	// scrypt
	N, R, P int
	// pbkdf2 (HMAC-SHA256)
	C int
}

// bounds keep crafted parameters from turning verification into an unbounded
// DoS. Real wallets use N up to 1<<18 (262144), c up to a few hundred thousand.
const (
	maxScryptN = 1 << 22
	maxR       = 64
	maxP       = 64
	maxPBKDF2C = 1 << 24
	maxSalt    = 1 << 12
	maxCipher  = 1 << 20
)

// maxJSON bounds the keystore document Parse accepts; real keystores are a few
// hundred bytes, so this is generous while keeping a hostile input bounded.
const maxJSON = 1 << 20

// keystoreDoc mirrors the Web3 Secret Storage Definition v3 JSON. encoding/json
// matches object keys case-insensitively, so this also accepts the capitalized
// "Crypto" some older wallets (MyEtherWallet) emit.
type keystoreDoc struct {
	Version int `json:"version"`
	Crypto  struct {
		Cipher     string `json:"cipher"`
		Ciphertext string `json:"ciphertext"`
		KDF        string `json:"kdf"`
		MAC        string `json:"mac"`
		KDFParams  struct {
			DKLen int    `json:"dklen"`
			Salt  string `json:"salt"`
			N     int    `json:"n"` // scrypt cost
			R     int    `json:"r"`
			P     int    `json:"p"`
			C     int    `json:"c"`   // pbkdf2 iterations
			PRF   string `json:"prf"` // pbkdf2 pseudo-random function
		} `json:"kdfparams"`
	} `json:"crypto"`
}

// Parse reads a version-3 keystore JSON document and extracts the parameters
// needed to verify its passphrase. It validates structure and bounds only; it
// never derives a key or touches a password. Malformed input yields
// ErrMalformed; a well-formed keystore whose variant is not supported (a
// non-3 version, an unknown KDF or PRF) yields ErrUnsupported.
func Parse(doc []byte) (Params, error) {
	if len(doc) == 0 || len(doc) > maxJSON {
		return Params{}, xcrypto.ErrMalformed
	}
	var ks keystoreDoc
	if err := json.Unmarshal(doc, &ks); err != nil {
		return Params{}, xcrypto.ErrMalformed
	}
	if ks.Version != 3 {
		return Params{}, xcrypto.ErrUnsupported
	}
	c := ks.Crypto
	salt, err := decodeHex(c.KDFParams.Salt)
	if err != nil || len(salt) == 0 || len(salt) > maxSalt {
		return Params{}, xcrypto.ErrMalformed
	}
	ct, err := decodeHex(c.Ciphertext)
	if err != nil || len(ct) == 0 || len(ct) > maxCipher {
		return Params{}, xcrypto.ErrMalformed
	}
	mac, err := decodeHex(c.MAC)
	if err != nil || len(mac) != 32 { // Keccak-256 MAC
		return Params{}, xcrypto.ErrMalformed
	}
	dklen := c.KDFParams.DKLen
	if dklen == 0 {
		dklen = 32
	}
	if dklen < 32 { // need at least derivedKey[16:32] for the MAC
		return Params{}, xcrypto.ErrMalformed
	}
	p := Params{Salt: salt, DKLen: dklen, Ciphertext: ct, MAC: mac}
	switch strings.ToLower(c.KDF) {
	case "scrypt":
		p.KDF = KDFScrypt
		p.N, p.R, p.P = c.KDFParams.N, c.KDFParams.R, c.KDFParams.P
	case "pbkdf2":
		p.KDF = KDFPBKDF2
		if prf := strings.ToLower(c.KDFParams.PRF); prf != "" && prf != "hmac-sha256" {
			return Params{}, xcrypto.ErrUnsupported // only HMAC-SHA256 PBKDF2 is defined for v3
		}
		p.C = c.KDFParams.C
	default:
		return Params{}, xcrypto.ErrUnsupported
	}
	return p, nil
}

// decodeHex decodes a keystore hex field, tolerating an optional 0x prefix.
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	return hex.DecodeString(s)
}

// SchemeName returns the Challenge scheme identifier.
func (p Params) SchemeName() string {
	if p.KDF == KDFPBKDF2 {
		return "ethkeystore-pbkdf2"
	}
	return "ethkeystore-scrypt"
}

// derive runs the configured KDF, returning the 32-byte derived key.
func (p Params) derive(password []byte) ([]byte, error) {
	dklen := p.DKLen
	if dklen <= 0 {
		dklen = 32
	}
	if len(p.Salt) == 0 || len(p.Salt) > maxSalt {
		return nil, xcrypto.ErrMalformed
	}
	switch p.KDF {
	case KDFScrypt:
		if p.N < 2 || p.N > maxScryptN || p.N&(p.N-1) != 0 || // N must be a power of two > 1
			p.R < 1 || p.R > maxR || p.P < 1 || p.P > maxP {
			return nil, xcrypto.ErrUnsupported
		}
		return scrypt.Key(password, p.Salt, p.N, p.R, p.P, dklen)
	case KDFPBKDF2:
		if p.C < 1 || p.C > maxPBKDF2C {
			return nil, xcrypto.ErrUnsupported
		}
		return prim.PBKDF2(sha256.New, string(password), p.Salt, p.C, dklen)
	default:
		return nil, xcrypto.ErrUnsupported
	}
}

// Verify reports whether password is the keystore passphrase: derive the key,
// recompute MAC = Keccak-256(derivedKey[16:32] || ciphertext), and compare it in
// constant time to the stored MAC.
func Verify(password []byte, p Params) (bool, error) {
	if len(p.MAC) == 0 || len(p.Ciphertext) == 0 || len(p.Ciphertext) > maxCipher {
		return false, nil
	}
	dk, err := p.derive(password)
	if err != nil {
		return false, err
	}
	if len(dk) < 32 {
		return false, nil
	}
	h := sha3.NewLegacyKeccak256() // Ethereum uses original Keccak, not NIST SHA3-256
	h.Write(dk[16:32])
	h.Write(p.Ciphertext)
	return prim.ConstantTimeEqual(h.Sum(nil), p.MAC), nil
}

// Challenge returns a reporting challenge for a keystore.
func (p Params) Challenge() *xcrypto.Challenge {
	iters := p.C
	algo := "pbkdf2-hmac-sha256"
	if p.KDF == KDFScrypt {
		iters = p.N
		algo = "scrypt"
	}
	return &xcrypto.Challenge{
		Scheme:   p.SchemeName(),
		KDF:      xcrypto.KDFSpec{Algo: algo, Iterations: iters, Salt: append([]byte(nil), p.Salt...), KeyLen: 32},
		Cipher:   xcrypto.CipherSpec{Algo: "aes-128-ctr", KeyBits: 128},
		Verifier: append([]byte(nil), p.MAC...),
	}
}
