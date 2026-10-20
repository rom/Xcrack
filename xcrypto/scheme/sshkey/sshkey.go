// Package sshkey detects and cracks passphrase-protected OpenSSH private keys
// (the "openssh-key-v1" PEM format produced by ssh-keygen). The passphrase KDF
// is bcrypt-pbkdf and the bulk cipher is typically aes256-ctr; verification and
// decryption delegate to the vetted golang.org/x/crypto/ssh implementation (the
// same code ssh tools use), so a recovered passphrase is authoritative. Only the
// passphrase is attacked — never any asymmetric key.
package sshkey

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"

	"github.com/rom/xcrypto"
	"golang.org/x/crypto/ssh"
)

// ErrNotSSHKey means the input is not an OpenSSH private key.
var ErrNotSSHKey = errors.New("sshkey: not an OpenSSH private key")

// ErrNotEncrypted means the key is present but not passphrase-protected.
var ErrNotEncrypted = errors.New("sshkey: key is not encrypted")

const pemType = "OPENSSH PRIVATE KEY"
const magic = "openssh-key-v1\x00"

// maxRounds bounds the bcrypt-pbkdf round count from the kdfoptions. The field
// is a uint32, and the derivation is linear in it, so an unbounded value hangs.
// golang.org/x/crypto caps it at 1<<11 internally; enforcing it here keeps the
// bound independent of the dependency version. Real keys use ~16.
const maxRounds = 1 << 11

// Info describes a parsed OpenSSH private key's encryption parameters.
type Info struct {
	Cipher string // e.g. "aes256-ctr"
	KDF    string // e.g. "bcrypt"
	Salt   []byte
	Rounds uint32
	PEM    []byte // the original PEM bytes (needed to verify/decrypt)
}

// Parse decodes the PEM and reads the openssh-key-v1 header. It returns
// ErrNotSSHKey if the input is not such a key, and ErrNotEncrypted if the key
// carries no passphrase KDF.
func Parse(data []byte) (*Info, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemType {
		return nil, ErrNotSSHKey
	}
	b := block.Bytes
	if len(b) < len(magic) || string(b[:len(magic)]) != magic {
		return nil, ErrNotSSHKey
	}
	r := &reader{b: b[len(magic):]}
	cipher, ok1 := r.readString()
	kdf, ok2 := r.readString()
	kdfOpts, ok3 := r.readString()
	if !ok1 || !ok2 || !ok3 {
		return nil, ErrNotSSHKey
	}
	if string(kdf) == "none" || string(cipher) == "none" {
		return nil, ErrNotEncrypted
	}
	info := &Info{Cipher: string(cipher), KDF: string(kdf), PEM: append([]byte(nil), data...)}
	// kdfoptions for bcrypt: string salt, uint32 rounds.
	or := &reader{b: kdfOpts}
	if salt, ok := or.readString(); ok {
		info.Salt = append([]byte(nil), salt...)
	}
	if rounds, ok := or.readUint32(); ok {
		if rounds > maxRounds {
			return nil, ErrNotSSHKey // implausible bcrypt-pbkdf cost: refuse rather than hang
		}
		info.Rounds = rounds
	}
	return info, nil
}

// Verify reports whether passphrase decrypts the key, using x/crypto/ssh as the
// authoritative check (it runs bcrypt-pbkdf, decrypts, and validates the
// embedded check-ints and the key structure).
func Verify(pemBytes, passphrase []byte) (bool, error) {
	_, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	if err == nil {
		return true, nil
	}
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return false, nil // should not happen for an encrypted key, but be safe
	}
	// Any other error (wrong passphrase, "key is not password protected") is a
	// non-match, not a hard failure.
	return false, nil
}

// Decrypt returns the decrypted private key, re-encoded as an unencrypted PKCS#8
// PEM block (a standard, portable form). It requires the correct passphrase.
func Decrypt(pemBytes, passphrase []byte) ([]byte, error) {
	key, err := ssh.ParseRawPrivateKeyWithPassphrase(pemBytes, passphrase)
	if err != nil {
		return nil, err
	}
	// ssh returns a pointer for most key types; ed25519 may come back as a value.
	if k, ok := key.(*ed25519.PrivateKey); ok {
		key = *k
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// Challenge builds a reporting Challenge for a parsed key.
func Challenge(info *Info) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme: "openssh-key",
		KDF:    xcrypto.KDFSpec{Algo: "bcrypt-pbkdf", Iterations: int(info.Rounds), Salt: info.Salt},
		Cipher: xcrypto.CipherSpec{Algo: info.Cipher},
		Extra:  map[string][]byte{"pem": info.PEM},
	}
}

// --- minimal SSH wire reader ---

type reader struct{ b []byte }

func (r *reader) readUint32() (uint32, bool) {
	if len(r.b) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.b)
	r.b = r.b[4:]
	return v, true
}

func (r *reader) readString() ([]byte, bool) {
	n, ok := r.readUint32()
	if !ok || int(n) > len(r.b) {
		return nil, false
	}
	s := r.b[:n]
	r.b = r.b[n:]
	return s, true
}
