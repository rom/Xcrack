// Package vbaproject detects a Microsoft VBA project and recovers its
// project-protection password (the VBA IDE "lock project for viewing"
// password), per [MS-OVBA]. The password lives in the DPB field of the PROJECT
// stream inside the VBA storage of an OLE2/CFB compound file; the cryptography
// is in xcrypto/scheme/vbaproject.
//
// A VBA project rides inside other formats (a legacy .doc/.xls/.ppt CFB, or a
// macro-enabled OOXML .docm/.xlsm/.pptm whose word/vbaProject.bin part is itself
// a CFB). The top-level file is therefore already claimed by msoffice or the
// zip/ooxml path, so this format is NOT in the autodetecting default registry —
// it would fight those for every Office file. It is reachable explicitly via the
// CLI's `--as vbaproject` (xcrack.ForceRegistry) and the `xcrack vba-recover`
// subcommand, which also unwraps an OOXML zip to find vbaProject.bin.
//
// Recovery has three outcomes (MS-OVBA 2.3.1.16): no password; a plaintext
// password (recovered with no cracking); or a 4-byte-salted SHA-1 hash
// (SHA1(password||salt), a fast verify-only crack — John dynamic_24 /
// hashcat -m 110 --hex-salt). The VBA source is never encrypted, so nothing is
// decrypted: the password is the deliverable.
package vbaproject

import (
	"archive/zip"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"

	"github.com/rom/xcrypto"
	xvba "github.com/rom/xcrypto/scheme/vbaproject"
	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/internal/cfb"
)

// maxSize bounds the bytes read for recovery (a VBA-bearing document; the
// PROJECT stream and vbaProject.bin are tiny, but the carrier can be larger).
const maxSize = 1 << 28

// maxVBAPart bounds a vbaProject.bin extracted from an OOXML zip.
const maxVBAPart = 1 << 24

// ErrNoVBAPassword means no readable VBA project password was found (not a VBA
// carrier, no PROJECT stream, or no DPB field).
var ErrNoVBAPassword = errors.New("vbaproject: no VBA project password found")

// Result is the outcome of recovering a VBA project password.
type Result struct {
	Kind      xvba.Kind
	Plaintext string // when Kind == KindPlaintext
	Key       []byte // 4-byte salt, when Kind == KindHash
	Hash      []byte // 20-byte SHA-1, when Kind == KindHash
}

// ParseProject finds and decodes the VBA project password in data, which may be
// a raw OLE2/CFB file (a legacy document or a standalone vbaProject.bin) or an
// OOXML zip (.docm/.xlsm/.pptm) whose vbaProject.bin part is unwrapped. It
// returns ErrNoVBAPassword when no DPB field is present.
func ParseProject(data []byte) (Result, error) {
	cfbData, ok := vbaCFB(data)
	if !ok {
		return Result{}, ErrNoVBAPassword
	}
	f, err := cfb.Open(cfbData)
	if err != nil {
		return Result{}, ErrNoVBAPassword
	}
	proj, ok := f.Stream("PROJECT")
	if !ok {
		return Result{}, ErrNoVBAPassword
	}
	dpb, ok := dpbHex(proj)
	if !ok {
		return Result{}, ErrNoVBAPassword
	}
	raw, err := hex.DecodeString(dpb)
	if err != nil {
		return Result{}, ErrNoVBAPassword
	}
	pw, err := xvba.ParseDPB(raw)
	if err != nil {
		return Result{}, ErrNoVBAPassword
	}
	return Result{Kind: pw.Kind, Plaintext: string(pw.Plaintext), Key: pw.Key, Hash: pw.Hash}, nil
}

// vbaCFB returns the CFB bytes holding the VBA project: data itself when it is a
// CFB, or the vbaProject.bin member of an OOXML zip.
func vbaCFB(data []byte) ([]byte, bool) {
	if cfb.IsCFB(data) {
		return data, true
	}
	// OOXML macro-enabled document: a zip with a */vbaProject.bin part.
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, false
	}
	for _, zf := range zr.File {
		if !strings.EqualFold(partBase(zf.Name), "vbaProject.bin") {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			continue
		}
		part, err := io.ReadAll(io.LimitReader(rc, maxVBAPart))
		rc.Close()
		if err == nil && cfb.IsCFB(part) {
			return part, true
		}
	}
	return nil, false
}

func partBase(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[i+1:]
	}
	return name
}

// dpbHex extracts the hex value of the DPB="..." line from a PROJECT stream.
func dpbHex(proj []byte) (string, bool) {
	// The PROJECT stream is a small CRLF-delimited text stream; scan line by line.
	for _, line := range strings.Split(string(proj), "\n") {
		line = strings.TrimRight(line, "\r")
		if !strings.HasPrefix(line, "DPB=") {
			continue
		}
		v := strings.TrimPrefix(line, "DPB=")
		v = strings.Trim(v, "\"")
		v = strings.TrimSpace(v)
		if v == "" {
			return "", false
		}
		return v, true
	}
	return "", false
}

// Format is the force-only VBA project password format.
type Format struct{}

// New returns a vbaproject Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry. Callers use this only for a registry
// that targets VBA explicitly (ForceRegistry) — never the autodetecting default.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "vbaproject" }

// Caps implements xfileformats.Format: whole-file password-protected (the
// "file" being the VBA project carrier).
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect greedily claims any CFB or zip input: a VBA project cannot be told from
// its carrier by a head peek, so this format is only ever consulted when forced.
func (f *Format) Detect(peek []byte) (float64, bool) {
	if cfb.IsCFB(peek) || (len(peek) >= 2 && peek[0] == 'P' && peek[1] == 'K') {
		return 1.0, true
	}
	return 0, false
}

// Probe reads the carrier, decodes the DPB field, and returns a Challenge for
// the hashed case (the salted SHA-1 verifier) or the plaintext case (the
// recovered password carried as the Hint so the engine tries it immediately).
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	if size <= 0 || size > maxSize {
		return nil, xfileformats.ErrMalformed
	}
	buf := make([]byte, size)
	n, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, xfileformats.ErrMalformed
	}
	res, err := ParseProject(buf[:n])
	if err != nil {
		return nil, xfileformats.ErrUnknownFormat
	}
	switch res.Kind {
	case xvba.KindHash:
		return xvba.Challenge(res.Key, res.Hash), nil
	case xvba.KindPlaintext:
		// No cracking needed: carry the recovered password as the Hint so the
		// engine's hint path tries it first, and verify against it exactly.
		return &xcrypto.Challenge{
			Scheme: "vba-project-plaintext",
			KDF:    xcrypto.KDFSpec{Algo: "none"},
			Hint:   res.Plaintext,
			Extra:  map[string][]byte{"plaintext": []byte(res.Plaintext)},
		}, nil
	default: // KindNone
		return nil, xfileformats.ErrUnknownFormat
	}
}

// Verify tests a candidate against the probed Challenge.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	switch ch.Scheme {
	case "vba-project":
		if xvba.Verify(ch.Extra["key"], ch.Extra["hash"], password) {
			return true, append([]byte(nil), password...), nil
		}
	case "vba-project-plaintext":
		if bytes.Equal(password, ch.Extra["plaintext"]) {
			return true, append([]byte(nil), password...), nil
		}
	}
	return false, nil, nil
}

// Decrypt has nothing to surface: the VBA source is not encrypted and the
// recovered password is the deliverable.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(nil), nil
}
