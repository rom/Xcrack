// Package sqlcipher wraps the xcrypto/scheme/sqlcipher passphrase verifier as an
// xfileformats format. SQLCipher databases carry no cleartext magic (the file
// starts with the random KDF salt), so this format is deliberately NOT in the
// default registry — it would claim every file. It is reachable only when the
// caller targets it explicitly (the CLI's `--as sqlcipher`, or xcrack.ForceRegistry),
// at which point its Detect greedily claims the input and Probe/Verify try the
// SQLCipher v4 and v3 profiles via the page-1 HMAC. Verify-only: the recovered
// passphrase is the deliverable; the database body is not reconstructed.
package sqlcipher

import (
	"bytes"
	"io"

	"github.com/rom/xcrypto"
	xsql "github.com/rom/xcrypto/scheme/sqlcipher"
	"github.com/rom/xfileformats"
)

// maxProbe bounds the page-1 bytes read for verification (the largest default
// profile page is 4096; read a little more so a custom page size still fits).
const maxProbe = 1 << 16

// Format is the SQLCipher passphrase-recovery format.
type Format struct{}

// New returns a SQLCipher Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry. Callers use this only for a registry
// that targets SQLCipher explicitly — never the autodetecting default one.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "sqlcipher" }

// Caps implements xfileformats.Format: whole-file password-protected.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect greedily claims any input: SQLCipher files have no magic, so this
// format is only ever consulted when the caller has forced it.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if len(peek) == 0 {
		return 0, false
	}
	return 1.0, true
}

// Probe reads page 1 (enough for both profiles) into the Challenge.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	n := size
	if n <= 0 {
		return nil, xfileformats.ErrMalformed
	}
	if n > maxProbe {
		n = maxProbe
	}
	buf := make([]byte, n)
	read, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, xfileformats.ErrMalformed
	}
	return &xcrypto.Challenge{Scheme: "sqlcipher", Extra: map[string][]byte{"page1": buf[:read]}}, nil
}

// Verify tries the default SQLCipher profiles (v4 then v3) against page 1.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	if _, ok := xsql.VerifyAny(ch.Extra["page1"], password, xsql.DefaultProfiles()); ok {
		return true, append([]byte(nil), password...), nil
	}
	return false, nil, nil
}

// Decrypt has nothing to surface — the recovered passphrase is the deliverable
// and the database body is not reconstructed — so it returns an empty reader.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(nil), nil
}
