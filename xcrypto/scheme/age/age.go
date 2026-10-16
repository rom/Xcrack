// Package age implements decryption of age files (age-encryption.org/v1) that
// use a passphrase (the "scrypt" recipient stanza). The file key is wrapped with
// ChaCha20-Poly1305 under a scrypt-derived key; the payload is a STREAM of
// ChaCha20-Poly1305 chunks keyed via HKDF-SHA256. Public-key (X25519) age files
// are out of scope -- they need a private key, not a password.
//
// This is an "extended" scheme: it uses golang.org/x/crypto for scrypt,
// ChaCha20-Poly1305, and HKDF (see CON-5).
package age

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"

	"github.com/rom/xcrypto"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// Magic is the age v1 header line.
const Magic = "age-encryption.org/v1"

const (
	scryptLabel  = "age-encryption.org/v1/scrypt"
	maxLogN      = 22        // bomb guard: cap scrypt work factor (age default is 18)
	chunkSize    = 64 * 1024 // age STREAM plaintext chunk size
	maxPayload   = 1 << 31   // cap decrypted payload
	maxHeaderLen = 1 << 20
)

var b64 = base64.RawStdEncoding

// Params are the parsed age-scrypt parameters.
type Params struct {
	Salt       []byte // 16-byte stanza salt (scrypt salt is label||Salt)
	LogN       int
	WrappedKey []byte // 32 bytes: ChaCha20-Poly1305(scryptKey, 0-nonce, fileKey)
	MACInput   []byte // header bytes through "---" (HMAC input)
	MAC        []byte // expected 32-byte header MAC
	Payload    []byte // binary payload: 16-byte nonce + STREAM chunks
}

// Parse reads an age file and extracts the scrypt stanza parameters. It returns
// ErrNotAge for non-age input and ErrUnsupported for age files without a scrypt
// (passphrase) recipient.
func Parse(data []byte) (*Params, error) {
	data = dearmor(data)
	if !bytes.HasPrefix(data, []byte(Magic+"\n")) {
		return nil, ErrNotAge
	}
	// The header MAC covers everything through the "---" marker.
	marker := []byte("\n--- ")
	idx := bytes.Index(data, marker)
	if idx < 0 || idx > maxHeaderLen {
		return nil, xcrypto.ErrMalformed
	}
	macInput := data[:idx+4] // include "\n---"
	// Footer line: "--- <b64 mac>\n"
	rest := data[idx+5:] // after "\n--- "
	nl := bytes.IndexByte(rest, '\n')
	if nl < 0 {
		return nil, xcrypto.ErrMalformed
	}
	mac, err := b64.DecodeString(string(rest[:nl]))
	if err != nil || len(mac) != 32 {
		return nil, xcrypto.ErrMalformed
	}
	payload := rest[nl+1:]

	// Parse stanzas from the header text for a scrypt recipient.
	header := data[len(Magic)+1 : idx+1] // stanzas region, each line \n-terminated
	p := &Params{MACInput: macInput, MAC: mac, Payload: payload}
	if err := parseScryptStanza(header, p); err != nil {
		return nil, err
	}
	return p, nil
}

func parseScryptStanza(header []byte, p *Params) error {
	lines := bytes.Split(header, []byte("\n"))
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !bytes.HasPrefix(line, []byte("-> ")) {
			continue
		}
		args := bytes.Fields(line[3:])
		// Collect the body: subsequent lines until one shorter than 64 chars.
		var body []byte
		for i+1 < len(lines) {
			bl := lines[i+1]
			if bytes.HasPrefix(bl, []byte("-> ")) {
				break
			}
			i++
			body = append(body, bl...)
			if len(bl) < 64 {
				break
			}
		}
		if len(args) == 3 && string(args[0]) == "scrypt" {
			salt, err := b64.DecodeString(string(args[1]))
			if err != nil || len(salt) != 16 {
				return xcrypto.ErrMalformed
			}
			logN, err := atoiBounded(string(args[2]))
			if err != nil {
				return xcrypto.ErrMalformed
			}
			if logN > maxLogN {
				return ErrUnsupported // work factor too high (bomb guard)
			}
			wrapped, err := b64.DecodeString(string(body))
			if err != nil || len(wrapped) != 32 {
				return xcrypto.ErrMalformed
			}
			p.Salt = salt
			p.LogN = logN
			p.WrappedKey = wrapped
			return nil
		}
	}
	return ErrUnsupported // no scrypt (passphrase) recipient
}

// FileKey derives and unwraps the age file key from a passphrase. It returns
// (nil, false, nil) for a wrong passphrase (the stanza AEAD tag fails).
func FileKey(password []byte, p *Params) ([]byte, bool, error) {
	if p.LogN <= 0 || p.LogN > maxLogN || len(p.Salt) != 16 {
		return nil, false, xcrypto.ErrUnsupported
	}
	salt := append([]byte(scryptLabel), p.Salt...)
	key, err := scrypt.Key(password, salt, 1<<p.LogN, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, false, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, false, err
	}
	nonce := make([]byte, aead.NonceSize())
	fileKey, err := aead.Open(nil, nonce, p.WrappedKey, nil)
	if err != nil {
		return nil, false, nil // wrong passphrase
	}
	return fileKey, true, nil
}

// VerifyMAC checks the header MAC with a derived file key. A correct passphrase
// whose file key fails the MAC means a corrupted/forged header.
func VerifyMAC(fileKey []byte, p *Params) bool {
	hmacKey := hkdfKey(fileKey, nil, "header")
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(p.MACInput)
	return hmac.Equal(mac.Sum(nil), p.MAC)
}

// Decrypt decrypts the payload with a verified file key.
func Decrypt(fileKey []byte, p *Params) ([]byte, error) {
	if len(p.Payload) < 16 {
		return nil, xcrypto.ErrMalformed
	}
	nonce := p.Payload[:16]
	body := p.Payload[16:]
	streamKey := hkdfKey(fileKey, nonce, "payload")
	aead, err := chacha20poly1305.New(streamKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body))
	chunkNonce := make([]byte, 12)
	var counter uint64
	encChunk := chunkSize + aead.Overhead()
	for off := 0; off < len(body); {
		end := off + encChunk
		last := false
		if end >= len(body) {
			end = len(body)
			last = true
		}
		writeCounter(chunkNonce, counter)
		if last {
			chunkNonce[11] = 0x01
		}
		pt, err := aead.Open(nil, chunkNonce, body[off:end], nil)
		if err != nil {
			return nil, xcrypto.ErrWrongPassword
		}
		out = append(out, pt...)
		if int64(len(out)) > maxPayload {
			return nil, xcrypto.ErrMalformed
		}
		off = end
		counter++
	}
	return out, nil
}

// Challenge builds a reporting + external-cracking challenge for an age file.
func Challenge(p *Params) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme:   "age-scrypt",
		KDF:      xcrypto.KDFSpec{Algo: "scrypt", Iterations: p.LogN, Salt: p.Salt, KeyLen: 32},
		Cipher:   xcrypto.CipherSpec{Algo: "chacha20-poly1305", KeyBits: 256},
		Verifier: p.MAC,
		Extra:    map[string][]byte{"wrapped_key": p.WrappedKey},
	}
}

func hkdfKey(secret, salt []byte, info string) []byte {
	r := hkdf.New(sha256.New, secret, salt, []byte(info))
	out := make([]byte, 32)
	io.ReadFull(r, out)
	return out
}

func writeCounter(nonce []byte, counter uint64) {
	for i := range nonce {
		nonce[i] = 0
	}
	// 11-byte big-endian counter in bytes [0:11]; byte[11] is the last-chunk flag.
	for i := 0; i < 8; i++ {
		nonce[10-i] = byte(counter >> (8 * i))
	}
}

func atoiBounded(s string) (int, error) {
	if s == "" || len(s) > 3 {
		return 0, errors.New("bad int")
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("bad int")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

// ArmorBegin is the age ASCII-armor header line.
const ArmorBegin = "-----BEGIN AGE ENCRYPTED FILE-----"

const armorEnd = "-----END AGE ENCRYPTED FILE-----"

// dearmor decodes age ASCII armor to the binary file, or returns data unchanged
// if it is not armored.
func dearmor(data []byte) []byte {
	if !strings.HasPrefix(strings.TrimLeft(string(data), "\r\n "), ArmorBegin) {
		return data
	}
	var b strings.Builder
	in := false
	for _, ln := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(strings.TrimRight(ln, "\r"))
		switch {
		case t == ArmorBegin:
			in = true
		case t == armorEnd:
			dec, err := base64.StdEncoding.DecodeString(b.String())
			if err != nil {
				return data
			}
			return dec
		case in:
			b.WriteString(t)
		}
	}
	return data
}

// Errors.
var (
	ErrNotAge      = errors.New("age: not an age file")
	ErrUnsupported = xcrypto.ErrUnsupported
)
