// Package zip implements the ZIP container format for Xfileformats, including
// the two encryption schemes found in the wild (traditional PKWARE "ZipCrypto"
// and WinZip AES). Container parsing is delegated to the standard library's
// archive/zip; all cryptography is delegated to the xcrypto scheme packages.
// This file only wires the two together: it extracts each entry's crypto
// parameters and raw bytes, and builds the Verify/Open closures.
package zip

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path"
	"strings"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/winzipaes"
	"github.com/rom/xcrypto/scheme/zipcrypto"
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
	maxEntryRaw     int64 = 1 << 30 // 1 GiB raw per entry
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
			continue
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
		if !ok || p.KeyLen() == 0 {
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
	ch := zipcrypto.Challenge(int64(zf.UncompressedSize64))

	decryptPlain := func(password []byte) ([]byte, error) {
		raw, err := readRawBytes(zf, maxEntryRaw)
		if err != nil {
			return nil, err
		}
		if flags&0x8 == 0 && !zipcrypto.HeaderOK(password, raw, zipcrypto.CheckByte(flags, crc, dosTime)) {
			return nil, xcrypto.ErrWrongPassword
		}
		payload, err := zipcrypto.Decrypt(password, raw)
		if err != nil {
			return nil, err
		}
		return decompress(payload, method)
	}
	verify := func(password []byte) (bool, error) {
		plain, err := decryptPlain(password)
		if err != nil {
			if errors.Is(err, xfileformats.ErrMalformed) {
				return false, err // genuine read error
			}
			return false, nil // crypto/decode failure => wrong password
		}
		return crc32.ChecksumIEEE(plain) == crc, nil
	}
	open := func(password []byte) (io.Reader, error) {
		plain, err := decryptPlain(password)
		if err != nil {
			return nil, err
		}
		if crc32.ChecksumIEEE(plain) != crc {
			return nil, xcrypto.ErrWrongPassword
		}
		return bytes.NewReader(plain), nil
	}
	// keyRecover performs a known-plaintext key recovery (no password). `known` is
	// aligned to the start of the encrypted DATA stream (the compressed bytes; for
	// a STORED entry that is the file content itself). On success it rolls the
	// recovered state back over the 12-byte header, decrypts the whole entry, and
	// decompresses. The result's CRC is checked, so a wrong `known` (e.g. for a
	// DEFLATE entry whose compressed bytes are unknown) cannot yield a false hit.
	keyRecover := func(known []byte, offload any) (io.Reader, bool, error) {
		raw, err := readRawBytes(zf, maxEntryRaw)
		if err != nil {
			return nil, false, err
		}
		if len(raw) < zipcrypto.HeaderLen {
			return nil, false, nil
		}
		data := raw[zipcrypto.HeaderLen:]
		n := len(known)
		if n > len(data) {
			n = len(data)
		}
		if n < zipcrypto.MinKnownPlaintext {
			return nil, false, nil // not enough known plaintext to recover
		}
		var (
			keys zipcrypto.Keys
			ok   bool
		)
		if off, _ := offload.(zipcrypto.Offloader); off != nil {
			keys, ok, err = zipcrypto.RecoverKeysWith(known[:n], data[:n], off)
			if err != nil {
				return nil, false, err
			}
		} else {
			keys, ok = zipcrypto.RecoverKeys(known[:n], data[:n])
		}
		if !ok {
			return nil, false, nil
		}
		// keys = state before data[0]; roll back over the header to the entry start.
		start, _ := keys.RollBack(raw[:zipcrypto.HeaderLen])
		full := append([]byte(nil), raw...)
		start.Decrypt(full)
		plain, err := decompress(full[zipcrypto.HeaderLen:], method)
		if err != nil {
			return nil, false, nil // recovered keys but content did not decompress
		}
		if crc32.ChecksumIEEE(plain) != crc {
			return nil, false, nil // decompressed but CRC mismatch => not a real hit
		}
		return bytes.NewReader(plain), true, nil
	}
	return &xfileformats.Entry{
		Path: name, Size: int64(zf.UncompressedSize64),
		Encrypted: true, Challenge: ch, Verify: verify, Open: open, KeyRecover: keyRecover,
	}, nil
}

func (f *Format) makeAESEntry(zf *stdzip.File, name string, p winzipaes.Params) (*xfileformats.Entry, error) {
	if p.ActualMethod != methodStore && p.ActualMethod != methodDeflate {
		return nil, xfileformats.ErrUnsupported
	}
	crc := zf.CRC32
	ch := &xcrypto.Challenge{
		Scheme:            p.SchemeName(),
		KDF:               xcrypto.KDFSpec{Algo: "pbkdf2-hmac-sha1", Iterations: winzipaes.PBKDF2Iter, KeyLen: p.KeyLen()},
		Cipher:            xcrypto.CipherSpec{Algo: "aes-ctr", KeyBits: p.KeyLen() * 8},
		DecryptedSizeHint: int64(zf.UncompressedSize64),
	}
	if hdr, err := readRawBytes(zf, int64(p.SaltLen()+winzipaes.PWVerifLen)); err == nil && len(hdr) >= p.SaltLen()+winzipaes.PWVerifLen {
		ch.KDF.Salt = append([]byte(nil), hdr[:p.SaltLen()]...)
		ch.Verifier = append([]byte(nil), hdr[p.SaltLen():p.SaltLen()+winzipaes.PWVerifLen]...)
	}
	verify := func(password []byte) (bool, error) {
		raw, err := readRawBytes(zf, maxEntryRaw)
		if err != nil {
			return false, err
		}
		return winzipaes.Verify(password, p, raw)
	}
	open := func(password []byte) (io.Reader, error) {
		raw, err := readRawBytes(zf, maxEntryRaw)
		if err != nil {
			return nil, err
		}
		comp, err := winzipaes.Decrypt(password, p, raw)
		if err != nil {
			return nil, err
		}
		plain, err := decompress(comp, p.ActualMethod)
		if err != nil {
			return nil, err
		}
		if crc != 0 && crc32.ChecksumIEEE(plain) != crc { // AE-1 carries CRC; AE-2 does not
			return nil, xcrypto.ErrWrongPassword
		}
		return bytes.NewReader(plain), nil
	}
	return &xfileformats.Entry{
		Path: name, Size: int64(zf.UncompressedSize64),
		Encrypted: true, Challenge: ch, Verify: verify, Open: open,
	}, nil
}

// parseAESExtra scans the raw extra-field blob for the 0x9901 WinZip AES header.
func parseAESExtra(extra []byte) (winzipaes.Params, bool) {
	b := extra
	for len(b) >= 4 {
		id := binary.LittleEndian.Uint16(b[0:2])
		sz := int(binary.LittleEndian.Uint16(b[2:4]))
		if 4+sz > len(b) {
			return winzipaes.Params{}, false
		}
		if id == 0x9901 {
			if sz < 7 {
				return winzipaes.Params{}, false
			}
			body := b[4 : 4+sz]
			if binary.LittleEndian.Uint16(body[2:4]) != winzipaes.VendorAE {
				return winzipaes.Params{}, false
			}
			return winzipaes.Params{
				VendorVer:    binary.LittleEndian.Uint16(body[0:2]),
				Strength:     body[4],
				ActualMethod: binary.LittleEndian.Uint16(body[5:7]),
			}, true
		}
		b = b[4+sz:]
	}
	return winzipaes.Params{}, false
}

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

func decompress(data []byte, method uint16) ([]byte, error) {
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
	cleaned := strings.TrimPrefix(path.Clean("/"+name), "/")
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return cleaned
}
