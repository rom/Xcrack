// Package odf implements detection and decryption of password-protected
// OpenDocument files (LibreOffice / OpenOffice). An ODF file is a ZIP; when
// encrypted, individual entries are DEFLATE-compressed then encrypted, with the
// per-entry parameters in META-INF/manifest.xml. This format parses the ZIP and
// the manifest, delegates all cryptography to xcrypto/scheme/odf, and exposes
// each member as an entry (decrypting + inflating the encrypted ones). Modern
// AES-256-CBC ODF is supported; legacy Blowfish-CFB entries report unsupported.
package odf

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"encoding/base64"
	"encoding/xml"
	"io"
	"path"
	"strings"

	"github.com/rom/xcrypto"
	xodf "github.com/rom/xcrypto/scheme/odf"
	"github.com/rom/xfileformats"
)

const (
	maxEntries      = 100_000
	maxDecompressed = 1 << 30
)

// Format detects and decrypts encrypted ODF documents.
type Format struct{}

// New returns an ODF Format.
func New() *Format { return &Format{} }

// Register adds the ODF format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "odf" }

// Caps implements xfileformats.Format: ODF is a container with per-entry encryption.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

// Detect recognizes an ODF package: a ZIP whose first ("mimetype") entry holds
// an OpenDocument media type, which appears in the leading bytes.
func (f *Format) Detect(p []byte) (float64, bool) {
	if !bytes.HasPrefix(p, []byte("PK\x03\x04")) {
		return 0, false
	}
	if bytes.Contains(p, []byte("mimetype")) && bytes.Contains(p, []byte("vnd.oasis.opendocument")) {
		return 0.95, true // outrank the generic zip format
	}
	return 0, false
}

// manifest.xml model (local element/attribute names; the manifest: prefix is ignored).
type manifestXML struct {
	FileEntry []struct {
		FullPath string `xml:"full-path,attr"`
		Size     int64  `xml:"size,attr"`
		Enc      *struct {
			Checksum     string `xml:"checksum,attr"`
			ChecksumType string `xml:"checksum-type,attr"`
			Algorithm    struct {
				Name string `xml:"algorithm-name,attr"`
				IV   string `xml:"initialisation-vector,attr"`
			} `xml:"algorithm"`
			KeyDerivation struct {
				Name       string `xml:"key-derivation-name,attr"`
				KeySize    int    `xml:"key-size,attr"`
				Iterations int    `xml:"iteration-count,attr"`
				Salt       string `xml:"salt,attr"`
			} `xml:"key-derivation"`
			StartKey struct {
				Name    string `xml:"start-key-generation-name,attr"`
				KeySize int    `xml:"key-size,attr"`
			} `xml:"start-key-generation"`
		} `xml:"encryption-data"`
	} `xml:"file-entry"`
}

func (f *Format) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	zr, err := stdzip.NewReader(r, size)
	if err != nil {
		return nil, xfileformats.ErrMalformed
	}
	encByPath := parseManifest(zr)

	entries := make([]*xfileformats.Entry, 0, len(zr.File))
	for _, zf := range zr.File {
		if strings.HasSuffix(zf.Name, "/") {
			continue
		}
		name := sanitize(zf.Name)
		if name == "" {
			continue
		}
		if len(entries) >= maxEntries {
			break
		}
		if p, ok := encByPath[zf.Name]; ok {
			entries = append(entries, encryptedEntry(zf, name, p))
		} else {
			entries = append(entries, plainEntry(zf, name))
		}
	}
	return entries, nil
}

func parseManifest(zr *stdzip.Reader) map[string]xodf.EntryParams {
	out := map[string]xodf.EntryParams{}
	var mf *stdzip.File
	for _, zf := range zr.File {
		if zf.Name == "META-INF/manifest.xml" {
			mf = zf
			break
		}
	}
	if mf == nil {
		return out
	}
	rc, err := mf.Open()
	if err != nil {
		return out
	}
	defer rc.Close()
	data, err := io.ReadAll(io.LimitReader(rc, 8<<20))
	if err != nil {
		return out
	}
	var m manifestXML
	if xml.Unmarshal(data, &m) != nil {
		return out
	}
	for _, fe := range m.FileEntry {
		if fe.Enc == nil || fe.FullPath == "" {
			continue
		}
		b64 := func(s string) []byte { b, _ := base64.StdEncoding.DecodeString(s); return b }
		out[fe.FullPath] = xodf.EntryParams{
			Algorithm:        fe.Enc.Algorithm.Name,
			IV:               b64(fe.Enc.Algorithm.IV),
			Salt:             b64(fe.Enc.KeyDerivation.Salt),
			Iterations:       fe.Enc.KeyDerivation.Iterations,
			KeySize:          orDefault(fe.Enc.KeyDerivation.KeySize, 32),
			StartKeyHash:     fe.Enc.StartKey.Name,
			Checksum:         b64(fe.Enc.Checksum),
			ChecksumType:     fe.Enc.ChecksumType,
			UncompressedSize: fe.Size,
		}
	}
	return out
}

func encryptedEntry(zf *stdzip.File, name string, p xodf.EntryParams) *xfileformats.Entry {
	raw := func() ([]byte, error) {
		rc, err := zf.OpenRaw()
		if err != nil {
			return nil, xfileformats.ErrMalformed
		}
		return io.ReadAll(io.LimitReader(rc, maxDecompressed))
	}
	e := &xfileformats.Entry{
		Path:      name,
		Size:      p.UncompressedSize,
		Encrypted: true,
		Challenge: xodf.Challenge(p),
		Verify: func(password []byte) (bool, error) {
			b, err := raw()
			if err != nil {
				return false, err
			}
			return xodf.Verify(password, p, b)
		},
		Open: func(password []byte) (io.Reader, error) {
			b, err := raw()
			if err != nil {
				return nil, err
			}
			comp, err := xodf.DecryptCompressed(password, p, b)
			if err != nil {
				return nil, err
			}
			plain, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(comp)), maxDecompressed))
			if err != nil && err != io.ErrUnexpectedEOF {
				return nil, xcrypto.ErrWrongPassword
			}
			if p.UncompressedSize > 0 && int64(len(plain)) > p.UncompressedSize {
				plain = plain[:p.UncompressedSize]
			}
			return bytes.NewReader(plain), nil
		},
	}
	// Offload the dominant PBKDF2-HMAC-SHA1 spin to an accelerator when present:
	// ODF derives the content key from PBKDF2(sha(password)), so PreHash tells the
	// engine to hash each candidate first. Finish re-runs the authoritative CBC
	// checksum / GCM tag check on the derived key, so the device never decides
	// correctness.
	if preHash, keyLen, ok := xodf.AccelStartHash(p); ok {
		e.Accel = &xfileformats.AccelKDF{
			PreHash: preHash,
			PRF:     "sha1",
			Salt:    p.Salt,
			Iter:    p.Iterations,
			DKLen:   keyLen,
			Finish: func(dk, _ []byte) bool {
				b, err := raw()
				if err != nil {
					return false
				}
				ok, _ := xodf.VerifyWithKey(dk, p, b)
				return ok
			},
		}
	}
	return e
}

func plainEntry(zf *stdzip.File, name string) *xfileformats.Entry {
	return &xfileformats.Entry{
		Path: name,
		Size: int64(zf.UncompressedSize64),
		Open: func([]byte) (io.Reader, error) {
			rc, err := zf.Open()
			if err != nil {
				return nil, xfileformats.ErrMalformed
			}
			return io.LimitReader(rc, maxDecompressed), nil
		},
	}
}

func orDefault(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func sanitize(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	c := strings.TrimPrefix(path.Clean("/"+name), "/")
	if c == "." || c == ".." || strings.HasPrefix(c, "../") {
		return ""
	}
	return c
}
