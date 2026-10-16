// Package keepass detects KeePass KDBX4 databases (.kdbx, version 4) and
// recovers their master passphrase via the header HMAC (see
// xcrypto/scheme/keepass). The default Argon2d KDF, Argon2id, and the legacy
// AES-KDF are all handled. Only the passphrase is attacked; the inner database
// is surfaced unchanged (the recovered password is the deliverable).
package keepass

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/rom/xcrypto"
	xkeepass "github.com/rom/xcrypto/scheme/keepass"
	"github.com/rom/xfileformats"
)

// maxProbe bounds how much of the file we read to parse the header; KDBX4
// headers are tiny (well under a KiB), so this is generous.
const maxProbe = 1 << 20

// Format detects and recovers the passphrase of a KDBX4 database.
type Format struct{}

// New returns a keepass Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "keepass" }

// Caps implements xfileformats.Format: whole-file password-protected.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes the KDBX signature (0x9AA2D903, 0xB54BFB67).
func (f *Format) Detect(peek []byte) (float64, bool) {
	if len(peek) >= 8 &&
		binary.LittleEndian.Uint32(peek[0:]) == 0x9AA2D903 &&
		binary.LittleEndian.Uint32(peek[4:]) == 0xB54BFB67 {
		return 0.99, true
	}
	return 0, false
}

// Probe parses the KDBX4 header and returns a Challenge carrying the minimal
// bytes needed to verify a password (so Verify need not re-read the file).
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
	buf = buf[:read]
	k, err := xkeepass.Parse(buf)
	if err != nil {
		if errors.Is(err, xcrypto.ErrUnsupported) {
			return nil, xfileformats.ErrUnsupported
		}
		return nil, xfileformats.ErrUnknownFormat
	}
	ch := k.Challenge()
	if ch.Extra == nil {
		ch.Extra = map[string][]byte{}
	}
	ch.Extra["kdbx"] = k.Serialized()
	return ch, nil
}

// Verify tests one candidate passphrase by recomputing the header HMAC.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	k, err := xkeepass.Parse(ch.Extra["kdbx"])
	if err != nil {
		return false, nil, err
	}
	ok, err := k.Verify(password)
	if err != nil || !ok {
		return false, nil, err
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt surfaces the database header bytes unchanged. The recovered password
// is the deliverable; the inner KDBX database body is not reconstructed.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(ch.Extra["kdbx"]), nil
}
