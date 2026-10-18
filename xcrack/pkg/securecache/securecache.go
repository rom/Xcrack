// Package securecache stores the found-password cache (the "potfile": passwords
// recovered on earlier runs, tried first on later ones) on disk, optionally
// encrypted.
//
// Two on-disk forms are supported behind one Store API:
//
//   - Plaintext (the default, Sealer == nil): the historical newline-delimited
//     potfile. New entries are appended, so existing caches keep working.
//   - Sealed (Sealer != nil): the password set is encrypted with a random
//     AES-256-GCM data-encryption key (DEK), and the DEK is wrapped by the
//     Sealer. The only Sealer today is TPM-backed (see TPMSealer, built only
//     with -tags tpm): the DEK is sealed to the machine's TPM so the cache file
//     is useless if copied off the host. A sealed cache is rewritten in full on
//     each change (it is small), authenticated by GCM so tampering is detected.
//
// The encryption is opt-in: the zero behaviour (Sealer == nil) is the plaintext
// cache, unchanged.
package securecache

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ErrTPMUnavailable is returned by TPMSealer when the binary was built without
// TPM support (the default), or when no TPM device is usable.
var ErrTPMUnavailable = errors.New("securecache: TPM support is not built in (rebuild with -tags tpm) or no TPM device is available")

// ErrBadCache is returned when a sealed cache file is malformed or fails its
// authentication/unseal — never silently discarded, so a wrong key or a
// corrupted/tampered file is surfaced rather than overwritten.
var ErrBadCache = errors.New("securecache: cache file is corrupt, tampered, or sealed to a different TPM")

// Sealer wraps and unwraps the data-encryption key that protects a sealed cache.
// A Sealer must bind the key to something the attacker cannot carry off with the
// file (for the TPM sealer, the host's TPM). Implementations are used only at
// load and first-write, so they need not be fast.
type Sealer interface {
	// Seal wraps the 32-byte DEK, returning an opaque blob stored in the file.
	Seal(dek []byte) (blob []byte, err error)
	// Unseal recovers the DEK from a blob Seal produced on this machine.
	Unseal(blob []byte) (dek []byte, err error)
	// Name identifies the sealer in the file header (informational).
	Name() string
}

const (
	sealMagic = "XCSEAL1\n"
	dekLen    = 32 // AES-256
)

// Store is an in-memory set of recovered passwords backed by a file. It is safe
// for concurrent use. Passwords are kept in first-seen order.
type Store struct {
	path   string
	sealer Sealer // nil => plaintext

	mu    sync.Mutex
	known map[string]bool
	order []string
}

// Open loads the cache at path. sealer == nil opens (or starts) a plaintext
// potfile; a non-nil sealer opens a sealed cache, unsealing and decrypting it.
// A missing file yields an empty store. A present-but-unreadable sealed file is
// an error (ErrBadCache), so a bad key or tampering never silently starts fresh
// and overwrites the user's cache.
func Open(path string, sealer Sealer) (*Store, error) {
	s := &Store{path: path, sealer: sealer, known: map[string]bool{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var lines []string
	if sealer == nil {
		lines = splitLines(data)
	} else {
		if len(data) == 0 {
			return s, nil
		}
		lines, err = decryptSealed(data, sealer)
		if err != nil {
			return nil, err
		}
	}
	for _, line := range lines {
		s.addMem(line)
	}
	return s, nil
}

// Encrypted reports whether this store seals its file.
func (s *Store) Encrypted() bool { return s.sealer != nil }

// Passwords returns the known passwords in first-seen order.
func (s *Store) Passwords() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.order...)
}

// Add records any new passwords and persists the cache. For a plaintext cache
// the new entries are appended; for a sealed cache the whole file is rewritten
// (encrypted) atomically. Adding nothing new is a no-op (no write).
func (s *Store) Add(pws ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []string
	for _, pw := range pws {
		if s.addMem(pw) {
			fresh = append(fresh, pw)
		}
	}
	if len(fresh) == 0 {
		return nil
	}
	if s.sealer == nil {
		return appendLines(s.path, fresh)
	}
	return s.writeSealed()
}

// addMem adds pw to the in-memory set, returning true if it was new. The caller
// holds the lock (or is the single-threaded loader).
func (s *Store) addMem(pw string) bool {
	if pw == "" || s.known[pw] {
		return false
	}
	s.known[pw] = true
	s.order = append(s.order, pw)
	return true
}

// writeSealed encrypts the full password set under a fresh DEK, seals the DEK,
// and writes the file atomically (temp + rename, 0600).
func (s *Store) writeSealed() error {
	plain := []byte(strings.Join(s.order, "\n"))
	dek := make([]byte, dekLen)
	if _, err := rand.Read(dek); err != nil {
		return err
	}
	blob, err := s.sealer.Seal(dek)
	if err != nil {
		return fmt.Errorf("seal DEK: %w", err)
	}
	body, err := encryptSealed(plain, dek, blob, s.sealer.Name())
	if err != nil {
		return err
	}
	return writeFileAtomic(s.path, body)
}

// encryptSealed builds the sealed-file body:
//
//	magic | nameLen u16 | name | blobLen u32 | blob | nonce(12) | GCM(plain)
func encryptSealed(plain, dek, blob []byte, name string) ([]byte, error) {
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, []byte(sealMagic))
	var b []byte
	b = append(b, sealMagic...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(name)))
	b = append(b, name...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(blob)))
	b = append(b, blob...)
	b = append(b, nonce...)
	b = append(b, ct...)
	return b, nil
}

// decryptSealed parses and decrypts a sealed-file body.
func decryptSealed(data []byte, sealer Sealer) ([]string, error) {
	r := &reader{b: data}
	if string(r.take(len(sealMagic))) != sealMagic {
		return nil, ErrBadCache
	}
	nameLen := int(r.u16())
	r.take(nameLen) // name is informational; the active sealer is used to unseal
	blobLen := int(r.u32())
	blob := r.take(blobLen)
	if r.err {
		return nil, ErrBadCache
	}
	dek, err := sealer.Unseal(blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCache, err)
	}
	aead, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	ns := aead.NonceSize()
	rest := r.rest()
	if len(rest) < ns {
		return nil, ErrBadCache
	}
	nonce, ct := rest[:ns], rest[ns:]
	plain, err := aead.Open(nil, nonce, ct, []byte(sealMagic))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadCache, err)
	}
	return splitLines(plain), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// --- small helpers ----------------------------------------------------------

type reader struct {
	b   []byte
	off int
	err bool
}

func (r *reader) take(n int) []byte {
	if r.err || n < 0 || r.off+n > len(r.b) {
		r.err = true
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}
func (r *reader) u16() uint16 {
	b := r.take(2)
	if r.err {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
func (r *reader) u32() uint32 {
	b := r.take(4)
	if r.err {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}
func (r *reader) rest() []byte {
	if r.err {
		return nil
	}
	return r.b[r.off:]
}

func splitLines(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func appendLines(path string, lines []string) error {
	if dir := filepath.Dir(path); dir != "" {
		_ = os.MkdirAll(dir, 0o700)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := io.WriteString(f, l+"\n"); err != nil {
			return err
		}
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".xccache-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
