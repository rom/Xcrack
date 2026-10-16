// Package puttykey detects and cracks passphrase-protected PuTTY private keys
// (.ppk), versions 2 and 3. The passphrase is confirmed by the file's
// Private-MAC: the encrypted private section is decrypted, then an HMAC over the
// key fields (algorithm, encryption, comment, public blob, decrypted private
// blob) is recomputed and compared. v3 derives the cipher key/IV and MAC key with
// Argon2 (id/i); v2 uses the legacy SHA-1 schedule. Only the passphrase is
// attacked.
package puttykey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"strconv"
	"strings"

	"github.com/rom/xcrypto"
	"golang.org/x/crypto/argon2"
)

// ErrNotPPK means the input is not a PuTTY private key.
var ErrNotPPK = errors.New("puttykey: not a PuTTY private key")

// ErrNotEncrypted means the key carries no passphrase.
var ErrNotEncrypted = errors.New("puttykey: key is not encrypted")

// ErrUnsupported means an unsupported KDF/cipher (e.g. Argon2d).
var ErrUnsupported = errors.New("puttykey: unsupported KDF or cipher")

// Info holds the parsed .ppk fields needed to test a passphrase.
type Info struct {
	Version    int
	Algorithm  string
	Encryption string
	Comment    string
	PublicBlob []byte
	PrivBlob   []byte // encrypted private section
	MAC        []byte // expected Private-MAC

	// v3 Argon2 parameters.
	Argon2Type string
	Memory     uint32 // KiB
	Passes     uint32
	Parallel   uint8
	Salt       []byte
}

// Parse reads a .ppk file. Returns ErrNotEncrypted for an unencrypted key.
func Parse(data []byte) (*Info, error) {
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	kv := map[string]string{}
	var pub, priv []string
	version := 0
	for i := 0; i < len(lines); i++ {
		ln := lines[i]
		j := strings.Index(ln, ": ")
		if j < 0 {
			continue
		}
		k, v := ln[:j], ln[j+2:]
		switch {
		case strings.HasPrefix(k, "PuTTY-User-Key-File-"):
			n, err := strconv.Atoi(strings.TrimPrefix(k, "PuTTY-User-Key-File-"))
			if err != nil {
				return nil, ErrNotPPK
			}
			version = n
			kv["algorithm"] = v
		case k == "Public-Lines":
			n, _ := strconv.Atoi(v)
			for x := 0; x < n && i+1 < len(lines); x++ {
				i++
				pub = append(pub, lines[i])
			}
		case k == "Private-Lines":
			n, _ := strconv.Atoi(v)
			for x := 0; x < n && i+1 < len(lines); x++ {
				i++
				priv = append(priv, lines[i])
			}
		default:
			kv[k] = v
		}
	}
	if version != 2 && version != 3 {
		return nil, ErrNotPPK
	}
	enc := kv["Encryption"]
	if enc == "none" || enc == "" {
		return nil, ErrNotEncrypted
	}
	if enc != "aes256-cbc" {
		return nil, ErrUnsupported
	}
	pubBlob, err := base64.StdEncoding.DecodeString(strings.Join(pub, ""))
	if err != nil {
		return nil, ErrNotPPK
	}
	privBlob, err := base64.StdEncoding.DecodeString(strings.Join(priv, ""))
	if err != nil || len(privBlob) == 0 || len(privBlob)%16 != 0 {
		return nil, ErrNotPPK
	}
	mac, err := hex.DecodeString(kv["Private-MAC"])
	if err != nil || len(mac) == 0 {
		return nil, ErrNotPPK
	}
	info := &Info{
		Version: version, Algorithm: kv["algorithm"], Encryption: enc,
		Comment: kv["Comment"], PublicBlob: pubBlob, PrivBlob: privBlob, MAC: mac,
	}
	if version == 3 {
		info.Argon2Type = kv["Key-Derivation"]
		mem, _ := strconv.Atoi(kv["Argon2-Memory"])
		pas, _ := strconv.Atoi(kv["Argon2-Passes"])
		par, _ := strconv.Atoi(kv["Argon2-Parallelism"])
		info.Memory, info.Passes, info.Parallel = uint32(mem), uint32(pas), uint8(par)
		info.Salt, _ = hex.DecodeString(kv["Argon2-Salt"])
		if info.Argon2Type == "Argon2d" {
			return nil, ErrUnsupported // x/crypto provides only Argon2i/Argon2id
		}
	}
	return info, nil
}

// Verify reports whether passphrase produces the stored Private-MAC.
func Verify(info *Info, passphrase []byte) (bool, error) {
	key, iv, macKey, newHash, err := derive(info, passphrase)
	if err != nil {
		return false, err
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return false, err
	}
	if len(info.PrivBlob)%aes.BlockSize != 0 {
		return false, nil
	}
	plain := make([]byte, len(info.PrivBlob))
	cipher.NewCBCDecrypter(blk, iv).CryptBlocks(plain, info.PrivBlob)

	md := macData(info, plain)
	m := hmac.New(newHash, macKey)
	m.Write(md)
	return hmac.Equal(m.Sum(nil), info.MAC), nil
}

// derive produces the AES key, IV, MAC key, and MAC hash for the key's version.
func derive(info *Info, pw []byte) (key, iv, macKey []byte, newHash func() hash.Hash, err error) {
	switch info.Version {
	case 3:
		var out []byte
		switch info.Argon2Type {
		case "Argon2id", "":
			out = argon2.IDKey(pw, info.Salt, info.Passes, info.Memory, info.Parallel, 80)
		case "Argon2i":
			out = argon2.Key(pw, info.Salt, info.Passes, info.Memory, info.Parallel, 80)
		default:
			return nil, nil, nil, nil, ErrUnsupported
		}
		return out[0:32], out[32:48], out[48:80], sha256.New, nil
	case 2:
		// AES key: SHA1(BE32(0)||pw) || SHA1(BE32(1)||pw), truncated to 32 bytes.
		k := append(sha1sum(seq(0), pw), sha1sum(seq(1), pw)...)
		// MAC key: SHA1("putty-private-key-file-mac-key" || pw).
		mk := sha1sum([]byte("putty-private-key-file-mac-key"), pw)
		return k[:32], make([]byte, 16), mk, sha1.New, nil
	}
	return nil, nil, nil, nil, ErrNotPPK
}

func seq(n uint32) []byte { var b [4]byte; binary.BigEndian.PutUint32(b[:], n); return b[:] }

func sha1sum(parts ...[]byte) []byte {
	h := sha1.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// macData is the HMAC input: each field length-prefixed (SSH string form).
func macData(info *Info, privPlain []byte) []byte {
	var md []byte
	for _, s := range [][]byte{
		[]byte(info.Algorithm), []byte(info.Encryption), []byte(info.Comment),
		info.PublicBlob, privPlain,
	} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(s)))
		md = append(md, l[:]...)
		md = append(md, s...)
	}
	return md
}

// Challenge builds a reporting Challenge for a .ppk.
func Challenge(info *Info, raw []byte) *xcrypto.Challenge {
	algo := "putty-v2-sha1"
	if info.Version == 3 {
		algo = "putty-v3-" + strings.ToLower(nonEmpty(info.Argon2Type, "argon2id"))
	}
	return &xcrypto.Challenge{
		Scheme: "putty-ppk",
		KDF:    xcrypto.KDFSpec{Algo: algo, Salt: info.Salt, Iterations: int(info.Passes)},
		Extra:  map[string][]byte{"ppk": raw},
	}
}

// VerifyRaw parses and verifies in one call (for Challenge-based callers).
func VerifyRaw(data, passphrase []byte) (bool, error) {
	info, err := Parse(data)
	if err != nil {
		return false, err
	}
	return Verify(info, passphrase)
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
