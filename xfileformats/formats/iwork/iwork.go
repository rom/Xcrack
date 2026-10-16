// Package iwork detects password-protected Apple iWork documents (Pages,
// Numbers, Keynote — .pages/.numbers/.key) and recovers the passphrase. These
// are ZIP archives of IWA protobuf parts; a protected document carries a
// `.iwpv2` passphrase verifier. Only the passphrase is attacked — the document
// body is not reconstructed (so Decrypt returns the archive unchanged, with the
// recovered passphrase reported separately). All cryptography is delegated to
// xcrypto/scheme/iwork.
package iwork

import (
	stdzip "archive/zip"
	"bytes"
	"errors"
	"io"
	"strings"

	"github.com/rom/xcrypto"
	xiwork "github.com/rom/xcrypto/scheme/iwork"
	"github.com/rom/xfileformats"
)

const (
	maxArchive  = 1 << 30 // 1 GiB: iWork docs are modest; cap generously
	maxVerifier = 1 << 16 // the .iwpv2 is ~104 bytes
)

var magicLFH = []byte("PK\x03\x04")

// Format detects and cracks password-protected iWork documents.
type Format struct{}

// New returns an iwork Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "iwork" }

// Caps implements xfileformats.Format: whole-document passphrase protection.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect claims any local-file-header ZIP at a confidence just above the generic
// zip format, so Probe gets the chance to inspect the archive for the `.iwpv2`
// verifier. A non-iWork zip is declined in Probe (ErrUnknownFormat), letting the
// engine fall back to the generic zip handler. The ZIP central directory — where
// the `.iwpv2` member actually appears — is at the end of the file, not in the
// bounded peek, so detection cannot be more specific here.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.HasPrefix(peek, magicLFH) {
		return 0.92, true
	}
	return 0, false
}

// Probe opens the archive and looks for the `.iwpv2` verifier. It returns:
//   - a Challenge, when the document is an encrypted iWork document;
//   - ErrNotEncrypted, when it is an iWork document with no passphrase;
//   - ErrUnknownFormat, when it is not an iWork document (so the engine falls
//     back to the generic zip handler);
//   - ErrUnsupported, when it is an iWork document with a `.iwpv2` variant this
//     package does not implement.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	if size <= 0 || size > maxArchive {
		return nil, xfileformats.ErrUnknownFormat
	}
	zr, err := stdzip.NewReader(r, size)
	if err != nil {
		return nil, xfileformats.ErrUnknownFormat // not a valid zip => not iWork
	}
	var verifier, hint *stdzip.File
	isIWork := false
	for _, zf := range zr.File {
		switch {
		case zf.Name == xiwork.VerifierName:
			verifier = zf
		case zf.Name == xiwork.HintName:
			hint = zf
		case strings.HasPrefix(zf.Name, "Index/") && strings.HasSuffix(zf.Name, ".iwa"):
			isIWork = true
		}
	}
	if verifier == nil {
		if isIWork {
			return nil, xfileformats.ErrNotEncrypted // iWork document, no passphrase
		}
		return nil, xfileformats.ErrUnknownFormat // not an iWork document
	}
	raw, err := readMember(verifier, maxVerifier)
	if err != nil {
		return nil, xfileformats.ErrUnknownFormat
	}
	p, err := xiwork.Parse(raw)
	if err != nil {
		if errors.Is(err, xiwork.ErrUnsupported) {
			return nil, xfileformats.ErrUnsupported
		}
		return nil, xfileformats.ErrUnknownFormat
	}
	ch := xiwork.Challenge(p)
	if ch.Extra == nil {
		ch.Extra = map[string][]byte{}
	}
	ch.Extra["iwpv2"] = raw
	// The optional `.iwph` member is a plaintext password hint the user set; it is
	// untrusted and often equals (or strongly suggests) the passphrase.
	if hint != nil {
		if hb, herr := readMember(hint, maxVerifier); herr == nil {
			ch.Hint = sanitizeHint(hb)
		}
	}
	return ch, nil
}

// sanitizeHint trims an untrusted hint and drops control characters, capping its
// length. The result is only ever used to derive candidate strings.
func sanitizeHint(b []byte) string {
	const maxHint = 256
	if len(b) > maxHint {
		b = b[:maxHint]
	}
	s := strings.Map(func(r rune) rune {
		if r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, string(b))
	return strings.TrimSpace(s)
}

// Verify tests a passphrase against the probed `.iwpv2`.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	ok, err := xiwork.VerifyRaw(ch.Extra["iwpv2"], password)
	if err != nil || !ok {
		return false, nil, nil // a parse error here is not a "wrong password" signal
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt returns the archive unchanged: iWork document-body reconstruction is
// out of scope, so the deliverable is the recovered passphrase (reported by the
// engine), not decrypted content. Mirrors the key-store formats.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	if size <= 0 || size > maxArchive {
		return nil, xfileformats.ErrMalformed
	}
	buf := make([]byte, size)
	n, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, xfileformats.ErrMalformed
	}
	return bytes.NewReader(buf[:n]), nil
}

// readMember reads a zip member fully, bounded by limit.
func readMember(zf *stdzip.File, limit int64) ([]byte, error) {
	rc, err := zf.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(io.LimitReader(rc, limit))
}
