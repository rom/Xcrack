// Package zip implements the ZIP container format for Xfileformats, including
// decryption of the two encryption schemes found in the wild:
//
//   - Traditional PKWARE encryption ("ZipCrypto"), and
//   - WinZip AES (AE-1 / AE-2), AES-128/192/256.
//
// ZIP is modeled as a Container: encryption is per-entry, so each encrypted
// Entry carries its own Challenge and Verify/Open closures that accept a
// password. The package never searches for passwords -- that is the caller's
// job. Container parsing is delegated to the standard library's archive/zip
// (bounded and well-tested); only the crypto layer is implemented here.
package zip

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path"
	"strings"

	"github.com/rom/xfileformats"
)

const (
	methodStore   = 0
	methodDeflate = 8
	methodAES     = 99

	// Parse/allocation backstops. The Xcrack engine enforces the real,
	// configurable budget; these only stop a single malformed entry from
	// exhausting memory at the format layer.
	maxEntries            = 100_000
	maxEntryRaw     int64 = 1 << 30 // 1 GiB raw (compressed+encrypted) per entry
	maxDecompressed int64 = 1 << 30 // 1 GiB decompressed per entry
)

// Format is the ZIP format plugin.
type Format struct{}

// New returns a ZIP Format.
func New() *Format { return &Format{} }

// Register adds the ZIP format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "zip" }

// Caps implements xfileformats.Format. ZIP is a container; its encryption is
// per-entry, so the whole-file Encrypted capability is false.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

var (
	magicLFH  = []byte("PK\x03\x04")
	magicEOCD = []byte("PK\x05\x06")
	magicSpan = []byte("PK\x07\x08")
)

// Detect implements xfileformats.Format.
func (f *Format) Detect(peek []byte) (float64, bool) {
	switch {
	case bytes.HasPrefix(peek, magicLFH):
		return 0.9, true
	case bytes.HasPrefix(peek, magicEOCD), bytes.HasPrefix(peek, magicSpan):
		return 0.6, true
	}
	return 0, false
}

// Entries implements xfileformats.Container.
func (f *Format) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	zr, err := stdzip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
	}
	if len(zr.File) > maxEntries {
		return nil, xfileformats.ErrLimitExceeded
	}
	entries := make([]*xfileformats.Entry, 0, len(zr.File))
	for _, zf := range zr.File {
		if strings.HasSuffix(zf.Name, "/") {
			continue // directory
		}
		name := sanitizePath(zf.Name)
		if name == "" {
			continue // unsafe or empty name
		}
		e, err := f.makeEntry(zf, name)
		if err != nil {
			e = unsupportedEntry(zf, name, err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func (f *Format) makeEntry(zf *stdzip.File, name string) (*xfileformats.Entry, error) {
	if zf.Flags&0x1 == 0 {
		// not encrypted: let the standard library handle decompression
		e := &xfileformats.Entry{Path: name, Size: int64(zf.UncompressedSize64)}
		e.Open = func(_ []byte) (io.Reader, error) {
			rc, err := zf.Open()
			if err != nil {
				return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
			}
			return io.LimitReader(rc, maxDecompressed), nil
		}
		return e, nil
	}
	if zf.Method == methodAES {
		p, ok := parseAESExtra(zf.Extra)
		if !ok || p.keyLen() == 0 {
			return nil, xfileformats.ErrUnsupported
		}
		return f.makeAESEntry(zf, name, p)
	}
	return f.makeZipCryptoEntry(zf, name)
}

func (f *Format) makeZipCryptoEntry(zf *stdzip.File, name string) (*xfileformats.Entry, error) {
	method := zf.Method
	if method != methodStore && method != methodDeflate {
		return nil, xfileformats.ErrUnsupported
	}
	crc, flags, dosTime := zf.CRC32, zf.Flags, zf.ModifiedTime
	ch := &xfileformats.Challenge{
		Format:            "zip",
		Method:            "zipcrypto",
		KDF:               xfileformats.KDFSpec{Algo: "none"},
		Cipher:            xfileformats.CipherSpec{Algo: "rc4-pkware"},
		DecryptedSizeHint: int64(zf.UncompressedSize64),
	}
	decryptPlain := func(password []byte) ([]byte, error) {
		raw, err := readRawBytes(zf, maxEntryRaw)
		if err != nil {
			return nil, err
		}
		if len(raw) < pkHeaderLen {
			return nil, errWrongPassword
		}
		// Fast reject on the header check byte (only reliable when not streaming).
		if flags&0x8 == 0 {
			if _, ok := zipCryptoHeaderOK(password, raw, flags, crc, dosTime); !ok {
				return nil, errWrongPassword
			}
		}
		buf := make([]byte, len(raw))
		copy(buf, raw)
		k := newPkKeys(password)
		k.decrypt(buf)
		return decompress(buf[pkHeaderLen:], method, int64(zf.UncompressedSize64))
	}
	verify := func(password []byte) (bool, error) {
		plain, err := decryptPlain(password)
		if err != nil {
			// A genuine read error on the source is real; any crypto/decode
			// failure just means this password is wrong.
			if errors.Is(err, xfileformats.ErrMalformed) {
				return false, err
			}
			return false, nil
		}
		return crc32.ChecksumIEEE(plain) == crc, nil
	}
	open := func(password []byte) (io.Reader, error) {
		plain, err := decryptPlain(password)
		if err != nil {
			return nil, err
		}
		if crc32.ChecksumIEEE(plain) != crc {
			return nil, errWrongPassword
		}
		return bytes.NewReader(plain), nil
	}
	return &xfileformats.Entry{
		Path: name, Size: int64(zf.UncompressedSize64),
		Encrypted: true, Challenge: ch, Verify: verify, Open: open,
	}, nil
}

func (f *Format) makeAESEntry(zf *stdzip.File, name string, p aesParams) (*xfileformats.Entry, error) {
	if p.actualMethod != methodStore && p.actualMethod != methodDeflate {
		return nil, xfileformats.ErrUnsupported
	}
	saltLen := p.saltLen()
	crc := zf.CRC32
	ch := &xfileformats.Challenge{
		Format:            "zip",
		Method:            p.methodName(),
		KDF:               xfileformats.KDFSpec{Algo: "pbkdf2-hmac-sha1", Iterations: aesPBKDF2Iter, KeyLen: p.keyLen()},
		Cipher:            xfileformats.CipherSpec{Algo: "aes-ctr", KeyBits: p.keyLen() * 8},
		DecryptedSizeHint: int64(zf.UncompressedSize64),
	}
	if hdr, err := readRawBytes(zf, int64(saltLen+aesPWVerifLen)); err == nil && len(hdr) >= saltLen+aesPWVerifLen {
		ch.KDF.Salt = append([]byte(nil), hdr[:saltLen]...)
		ch.Verifier = append([]byte(nil), hdr[saltLen:saltLen+aesPWVerifLen]...)
	}
	split := func() (salt, pwv, ct, mac []byte, err error) {
		raw, err := readRawBytes(zf, maxEntryRaw)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if len(raw) < saltLen+aesPWVerifLen+aesMACLen {
			return nil, nil, nil, nil, xfileformats.ErrMalformed
		}
		salt = raw[:saltLen]
		pwv = raw[saltLen : saltLen+aesPWVerifLen]
		ct = raw[saltLen+aesPWVerifLen : len(raw)-aesMACLen]
		mac = raw[len(raw)-aesMACLen:]
		return salt, pwv, ct, mac, nil
	}
	verify := func(password []byte) (bool, error) {
		salt, pwv, ct, mac, err := split()
		if err != nil {
			return false, err
		}
		return aesVerify(password, p, salt, pwv, ct, mac)
	}
	open := func(password []byte) (io.Reader, error) {
		salt, pwv, ct, mac, err := split()
		if err != nil {
			return nil, err
		}
		comp, err := aesDecrypt(password, p, salt, pwv, ct, mac)
		if err != nil {
			return nil, err
		}
		plain, err := decompress(comp, p.actualMethod, int64(zf.UncompressedSize64))
		if err != nil {
			return nil, err
		}
		if crc != 0 && crc32.ChecksumIEEE(plain) != crc { // AE-1 carries CRC; AE-2 does not
			return nil, errWrongPassword
		}
		return bytes.NewReader(plain), nil
	}
	return &xfileformats.Entry{
		Path: name, Size: int64(zf.UncompressedSize64),
		Encrypted: true, Challenge: ch, Verify: verify, Open: open,
	}, nil
}

// unsupportedEntry represents an entry we recognized but cannot process, so the
// caller still sees it in the tree instead of losing it.
func unsupportedEntry(zf *stdzip.File, name string, cause error) *xfileformats.Entry {
	return &xfileformats.Entry{
		Path:      name,
		Size:      int64(zf.UncompressedSize64),
		Encrypted: zf.Flags&0x1 != 0,
		Verify:    func([]byte) (bool, error) { return false, cause },
		Open:      func([]byte) (io.Reader, error) { return nil, cause },
	}
}

func readRawBytes(zf *stdzip.File, limit int64) ([]byte, error) {
	rc, err := zf.OpenRaw()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
	}
	out, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
	}
	return out, nil
}

func decompress(data []byte, method uint16, _ int64) ([]byte, error) {
	switch method {
	case methodStore:
		return data, nil
	case methodDeflate:
		fr := flate.NewReader(bytes.NewReader(data))
		defer fr.Close()
		out, err := io.ReadAll(io.LimitReader(fr, maxDecompressed))
		if err != nil {
			return nil, err
		}
		return out, nil
	default:
		return nil, xfileformats.ErrUnsupported
	}
}

func sanitizePath(name string) string {
	name = strings.ReplaceAll(name, "\\", "/")
	// Force to an absolute path and clean it, which collapses any ".."
	// components so they cannot escape, then drop the leading slash.
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}
