// Package keepass implements passphrase recovery for KeePass KDBX4 databases
// (.kdbx, format version 4). A KDBX4 file authenticates its header with an
// HMAC-SHA256 whose key is derived from the master password through the chosen
// KDF — Argon2d (the default), Argon2id, or the legacy AES-KDF — so a password
// is verified by recomputing that header HMAC, with no need to decrypt the
// database body. Only verification is implemented; the inner database is not
// reconstructed.
//
// Master-key chain (password only):
//
//	composite      = SHA256( SHA256(password) )
//	transformed    = KDF(composite)                       // Argon2d/id or AES-KDF
//	hmacBaseKey    = SHA512( masterSeed || transformed || 0x01 )
//	headerBlockKey = SHA512( LE64(0xFFFFFFFFFFFFFFFF) || hmacBaseKey )
//	headerHMAC     = HMAC-SHA256( headerBlockKey, headerBytes )
//
// A password is correct iff headerHMAC equals the 32 bytes stored right after
// the header.
package keepass

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/prim/argon2"
)

const (
	sig1 = 0x9AA2D903
	sig2 = 0xB54BFB67

	hdrEndOfHeader   = 0
	hdrCipherID      = 2
	hdrCompression   = 3
	hdrMasterSeed    = 4
	hdrEncryptionIV  = 7
	hdrKdfParameters = 11

	// bounds against crafted parameters (verification is deliberately costly;
	// these keep a hostile file from turning it into an unbounded DoS).
	maxHeader     = 1 << 20
	maxKdfMemory  = 4 << 30 // 4 GiB of Argon2 memory
	maxKdfIters   = 1 << 24
	maxKdfThreads = 1 << 10
	maxAESRounds  = 1 << 30
)

// KDF UUIDs (16-byte, big-endian as written in the VariantDictionary).
var (
	uuidArgon2d  = [16]byte{0xEF, 0x63, 0x6D, 0xDF, 0x8C, 0x29, 0x44, 0x4B, 0x91, 0xF7, 0xA9, 0xA4, 0x03, 0xE3, 0x0A, 0x0C}
	uuidArgon2id = [16]byte{0x9E, 0x29, 0x8B, 0x19, 0x56, 0xDB, 0x47, 0x73, 0xB2, 0x3D, 0xFE, 0x5F, 0x03, 0xFA, 0x5C, 0xB1}
	uuidAESKDF   = [16]byte{0xC9, 0xD9, 0xF3, 0x9A, 0x62, 0x8A, 0x44, 0x60, 0xBF, 0x74, 0x0D, 0x08, 0xC1, 0x8A, 0x4F, 0xEA}
)

type kdfParams struct {
	uuid       [16]byte
	salt       []byte // Argon2 salt, or AES-KDF seed ("S")
	memoryKiB  uint64
	iterations uint64
	threads    uint32
	version    uint32
	aesRounds  uint64
}

// KDBX is a parsed KDBX4 database header sufficient to verify a password.
type KDBX struct {
	Minor, Major uint16
	header       []byte // raw header bytes, through the end-of-header field
	masterSeed   []byte
	storedHMAC   []byte
	kdfRaw       []byte // raw KdfParameters VariantDictionary, parsed by parseKDF
	kdf          kdfParams
	prefix       []byte // the minimal self-contained bytes (header + SHA + HMAC)
}

// Serialized returns the minimal leading bytes of the file needed to verify a
// password (the header plus the trailing SHA-256 and HMAC). A caller can stash
// this in a Challenge and re-Parse it per candidate instead of holding the
// whole database.
func (k *KDBX) Serialized() []byte { return k.prefix }

// vdVal is one VariantDictionary value: byte payload (bytes/string) or an
// unsigned integer (int/bool types, zero-extended to 64 bits).
type vdVal struct {
	b []byte
	u uint64
}

// parseVariantDict parses a KeePass VariantDictionary (a uint16 version followed
// by typed key/value entries, terminated by a 0 type byte).
func parseVariantDict(b []byte) (map[string]vdVal, error) {
	if len(b) < 2 {
		return nil, xcrypto.ErrMalformed
	}
	out := map[string]vdVal{}
	off := 2 // skip the version uint16
	for {
		if off >= len(b) {
			return nil, xcrypto.ErrMalformed
		}
		typ := b[off]
		off++
		if typ == 0 {
			return out, nil
		}
		if off+4 > len(b) {
			return nil, xcrypto.ErrMalformed
		}
		klen := int(le32(b[off:]))
		off += 4
		if klen < 0 || off+klen > len(b) {
			return nil, xcrypto.ErrMalformed
		}
		key := string(b[off : off+klen])
		off += klen
		if off+4 > len(b) {
			return nil, xcrypto.ErrMalformed
		}
		vlen := int(le32(b[off:]))
		off += 4
		if vlen < 0 || off+vlen > len(b) {
			return nil, xcrypto.ErrMalformed
		}
		val := b[off : off+vlen]
		off += vlen
		var vv vdVal
		switch typ {
		case 0x04, 0x0C: // UInt32, Int32
			if vlen >= 4 {
				vv.u = uint64(le32(val))
			}
		case 0x05, 0x0D: // UInt64, Int64
			if vlen >= 8 {
				vv.u = binary.LittleEndian.Uint64(val)
			}
		case 0x08: // Bool
			if vlen >= 1 && val[0] != 0 {
				vv.u = 1
			}
		case 0x42, 0x18: // ByteArray, String (UTF-8)
			vv.b = append([]byte(nil), val...)
		}
		out[key] = vv
	}
}

func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// Parse reads a KDBX4 file header and the stored header HMAC.
func Parse(data []byte) (*KDBX, error) {
	if len(data) < 12 || le32(data[0:]) != sig1 || le32(data[4:]) != sig2 {
		return nil, xcrypto.ErrMalformed
	}
	k := &KDBX{
		Minor: binary.LittleEndian.Uint16(data[8:]),
		Major: binary.LittleEndian.Uint16(data[10:]),
	}
	if k.Major != 4 {
		// KDBX3 uses a different (stream-start-bytes) verifier; not handled here.
		return nil, xcrypto.ErrUnsupported
	}
	off := 12
	for {
		if off+5 > len(data) {
			return nil, xcrypto.ErrMalformed
		}
		id := data[off]
		n := int(le32(data[off+1:]))
		off += 5
		if n < 0 || off+n > len(data) || off+n > maxHeader {
			return nil, xcrypto.ErrMalformed
		}
		field := data[off : off+n]
		off += n
		switch id {
		case hdrEndOfHeader:
			k.header = data[:off]
			if off+64 > len(data) {
				return nil, xcrypto.ErrMalformed
			}
			// data[off:off+32] is SHA-256(header) (integrity, password-independent);
			// data[off+32:off+64] is the header HMAC (the password verifier).
			k.storedHMAC = data[off+32 : off+64]
			k.prefix = append([]byte(nil), data[:off+64]...)
			if err := k.parseKDF(); err != nil {
				return nil, err
			}
			if len(k.masterSeed) != 32 {
				return nil, xcrypto.ErrMalformed
			}
			return k, nil
		case hdrMasterSeed:
			k.masterSeed = append([]byte(nil), field...)
		case hdrKdfParameters:
			k.kdfRaw = append([]byte(nil), field...)
		}
		if off > maxHeader {
			return nil, xcrypto.ErrMalformed
		}
	}
}

// kdfRaw holds the raw KdfParameters VariantDictionary until parseKDF runs.
// (kept on the struct so Parse's single pass can stash it)
func (k *KDBX) parseKDF() error {
	vd, err := parseVariantDict(k.kdfRaw)
	if err != nil {
		return err
	}
	p := kdfParams{}
	if u, ok := vd["$UUID"]; ok && len(u.b) == 16 {
		copy(p.uuid[:], u.b)
	} else {
		return xcrypto.ErrMalformed
	}
	if s, ok := vd["S"]; ok {
		p.salt = s.b
	}
	if v, ok := vd["M"]; ok {
		p.memoryKiB = v.u / 1024 // KDBX stores Argon2 memory in BYTES
	}
	if v, ok := vd["I"]; ok {
		p.iterations = v.u
	}
	if v, ok := vd["P"]; ok {
		p.threads = uint32(v.u)
	}
	if v, ok := vd["V"]; ok {
		p.version = uint32(v.u)
	}
	if v, ok := vd["R"]; ok {
		p.aesRounds = v.u
	}
	k.kdf = p
	return nil
}

// transformKey runs the configured KDF over the 32-byte composite key.
func (k *KDBX) transformKey(composite []byte) ([]byte, error) {
	p := k.kdf
	switch p.uuid {
	case uuidArgon2d, uuidArgon2id:
		if p.memoryKiB == 0 || p.memoryKiB > maxKdfMemory/1024 ||
			p.iterations == 0 || p.iterations > maxKdfIters ||
			p.threads == 0 || p.threads > maxKdfThreads {
			return nil, xcrypto.ErrUnsupported
		}
		m := uint32(p.memoryKiB)
		if p.uuid == uuidArgon2d {
			return argon2.Argon2d(composite, p.salt, uint32(p.iterations), m, uint8(p.threads), 32), nil
		}
		return argon2.Argon2id(composite, p.salt, uint32(p.iterations), m, uint8(p.threads), 32), nil
	case uuidAESKDF:
		if len(p.salt) != 32 || p.aesRounds == 0 || p.aesRounds > maxAESRounds {
			return nil, xcrypto.ErrUnsupported
		}
		return aesKDF(composite, p.salt, p.aesRounds)
	default:
		return nil, xcrypto.ErrUnsupported
	}
}

// aesKDF is the legacy KeePass key transform: encrypt the composite key with
// AES-256-ECB using the seed as key, `rounds` times, then SHA-256 the result.
func aesKDF(composite, seed []byte, rounds uint64) ([]byte, error) {
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	buf := append([]byte(nil), composite...) // 32 bytes = 2 AES blocks
	for i := uint64(0); i < rounds; i++ {
		block.Encrypt(buf[0:16], buf[0:16])
		block.Encrypt(buf[16:32], buf[16:32])
	}
	h := sha256.Sum256(buf)
	return h[:], nil
}

// Verify reports whether password unlocks the database, by recomputing the
// header HMAC. It is deliberately expensive (runs the KDF).
func (k *KDBX) Verify(password []byte) (bool, error) {
	pw := sha256.Sum256(password)
	composite := sha256.Sum256(pw[:])
	transformed, err := k.transformKey(composite[:])
	if err != nil {
		return false, err
	}
	// hmacBaseKey = SHA512(masterSeed || transformed || 0x01)
	hb := sha512.New()
	hb.Write(k.masterSeed)
	hb.Write(transformed)
	hb.Write([]byte{0x01})
	hmacBase := hb.Sum(nil)
	// headerBlockKey = SHA512(LE64(0xFFFFFFFFFFFFFFFF) || hmacBaseKey)
	bk := sha512.New()
	bk.Write([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	bk.Write(hmacBase)
	blockKey := bk.Sum(nil)
	mac := hmac.New(sha256.New, blockKey)
	mac.Write(k.header)
	got := mac.Sum(nil)
	return subtle.ConstantTimeCompare(got, k.storedHMAC) == 1, nil
}

// Challenge returns a reporting challenge for a KDBX4 database.
func (k *KDBX) Challenge() *xcrypto.Challenge {
	algo := "keepass-kdbx4-"
	switch k.kdf.uuid {
	case uuidArgon2d:
		algo += "argon2d"
	case uuidArgon2id:
		algo += "argon2id"
	case uuidAESKDF:
		algo += "aeskdf"
	default:
		algo += "unknown"
	}
	return &xcrypto.Challenge{
		Scheme:   algo,
		KDF:      xcrypto.KDFSpec{Algo: algo, Iterations: int(k.kdf.iterations), Salt: k.kdf.salt, KeyLen: 32},
		Cipher:   xcrypto.CipherSpec{Algo: "aes-256", KeyBits: 256},
		Verifier: k.storedHMAC,
	}
}
