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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"path"
	"strings"
	"sync"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/hashline"
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

// zipHint normalizes an untrusted ZIP entry comment into a password hint: it
// trims whitespace, drops control characters, and caps the length. Empty when
// there is no useful comment.
func zipHint(comment string) string {
	const maxHint = 256
	if comment == "" {
		return ""
	}
	if len(comment) > maxHint {
		comment = comment[:maxHint]
	}
	s := strings.Map(func(r rune) rune {
		if r == '\t' || (r >= 0x20 && r != 0x7f) {
			return r
		}
		return -1
	}, comment)
	return strings.TrimSpace(s)
}

func (f *Format) makeZipCryptoEntry(zf *stdzip.File, name string) (*xfileformats.Entry, error) {
	method := zf.Method
	if method != methodStore && method != methodDeflate {
		return nil, xfileformats.ErrUnsupported
	}
	crc, flags, dosTime := zf.CRC32, zf.Flags, zf.ModifiedTime
	ch := zipcrypto.Challenge(int64(zf.UncompressedSize64))
	ch.Hint = zipHint(zf.Comment) // a per-entry comment is sometimes a password hint

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
	keyRecover := func(ctx context.Context, known []byte, offload any) (io.Reader, bool, error) {
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
			keys, ok, err = zipcrypto.RecoverKeysWith(ctx, known[:n], data[:n], off)
			if err != nil {
				return nil, false, err
			}
		} else {
			keys, ok = zipcrypto.RecoverKeysCtx(ctx, known[:n], data[:n])
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
		Hint:              zipHint(zf.Comment),
	}
	var salt []byte
	if hdr, err := readRawBytes(zf, int64(p.SaltLen()+winzipaes.PWVerifLen)); err == nil && len(hdr) >= p.SaltLen()+winzipaes.PWVerifLen {
		salt = append([]byte(nil), hdr[:p.SaltLen()]...)
		ch.KDF.Salt = salt
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
	e := &xfileformats.Entry{
		Path: name, Size: int64(zf.UncompressedSize64),
		Encrypted: true, Challenge: ch, Verify: verify, Open: open,
	}
	// Expose the batchable PBKDF2-HMAC-SHA1 derivation so the engine can offload
	// the keyspace sweep to a GPU tier. WinZip-AES derives enc||auth||verifier in
	// one 1000-iteration PBKDF2 over the entry salt; Finish re-runs the exact
	// verifier+HMAC check on the derived key. The raw entry (ciphertext+MAC) is
	// read once and cached, since Finish is called per candidate. Only offered
	// when the header salt was readable (otherwise no acceleration — the CPU path
	// re-reads the whole entry itself).
	if salt != nil {
		var (
			rawOnce sync.Once
			rawBuf  []byte
			rawErr  error
		)
		loadRaw := func() ([]byte, error) {
			rawOnce.Do(func() { rawBuf, rawErr = readRawBytes(zf, maxEntryRaw) })
			return rawBuf, rawErr
		}
		e.Accel = &xfileformats.AccelKDF{
			Salt:  salt,
			Iter:  winzipaes.PBKDF2Iter,
			DKLen: 2*p.KeyLen() + winzipaes.PWVerifLen,
			Finish: func(dk, _ []byte) bool {
				raw, err := loadRaw()
				if err != nil {
					return false
				}
				ok, _ := winzipaes.VerifyWithDK(dk, p, raw)
				return ok
			},
		}
	}
	return e, nil
}

// HashcatLines implements hashline.LineExporter: it emits a crackable $zip2$
// line (hashcat -m 13600) for every WinZip-AES entry in the archive. Unlike the
// probe-time Challenge — which carries only the header (salt + 2-byte verifier)
// so the engine's fast reject stays cheap — this reads the full raw entry and
// includes the ciphertext and 10-byte authentication code a GPU cracker needs.
// Unencrypted, ZipCrypto, and otherwise-unsupported entries are skipped; a
// per-entry read or split failure skips that entry rather than failing the
// whole file.
func (f *Format) HashcatLines(r io.ReaderAt, size int64) ([]hashline.Labeled, error) {
	zr, err := stdzip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
	}
	if len(zr.File) > maxEntries {
		return nil, xfileformats.ErrLimitExceeded
	}
	var out []hashline.Labeled
	for _, zf := range zr.File {
		if strings.HasSuffix(zf.Name, "/") || zf.Flags&0x1 == 0 || zf.Method != methodAES {
			continue
		}
		name := sanitizePath(zf.Name)
		if name == "" {
			continue
		}
		p, ok := parseAESExtra(zf.Extra)
		if !ok || p.KeyLen() == 0 {
			continue
		}
		raw, err := readRawBytes(zf, maxEntryRaw)
		if err != nil {
			continue
		}
		salt, pwv, ct, mac, err := winzipaes.Split(p, raw)
		if err != nil {
			continue
		}
		res, ok := hashline.Zip2(p.KeyLen()*8, salt, pwv, ct, mac)
		if !ok {
			continue
		}
		out = append(out, hashline.Labeled{Target: name, Result: res})
	}
	return out, nil
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

// ArchivePlain is the decryption result for one traditional-ZipCrypto entry
// under a shared key state.
type ArchivePlain struct {
	Name      string
	Plaintext []byte
	OK        bool // the CRC matched — the shared key state is correct for this entry
}

// DecryptArchiveWithStart decrypts every traditional (PKWARE) ZipCrypto entry in
// an archive using one shared pre-entry key state `start`. Because ZipCrypto
// re-derives that state (NewKeys(password)) from the same password for every
// entry, `start` is identical across the whole archive: recover it once — from a
// single entry by password or Biham–Kocher known-plaintext — and the rest of the
// archive decrypts with no further search ("cross-entry key reuse"). Each entry's
// CRC-32 is re-checked, so a wrong `start` yields OK=false, never a false
// positive. AES and unencrypted entries are skipped (OK=false, no plaintext).
func DecryptArchiveWithStart(r io.ReaderAt, size int64, start zipcrypto.Keys) ([]ArchivePlain, error) {
	zr, err := stdzip.NewReader(r, size)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", xfileformats.ErrMalformed, err)
	}
	if len(zr.File) > maxEntries {
		return nil, xfileformats.ErrLimitExceeded
	}
	var out []ArchivePlain
	for _, zf := range zr.File {
		if strings.HasSuffix(zf.Name, "/") {
			continue
		}
		name := sanitizePath(zf.Name)
		if name == "" {
			continue
		}
		res := ArchivePlain{Name: name}
		// Only traditional ZipCrypto (encrypted, not AES, store/deflate).
		if zf.Flags&0x1 == 0 || zf.Method == methodAES ||
			(zf.Method != methodStore && zf.Method != methodDeflate) {
			out = append(out, res)
			continue
		}
		raw, rerr := readRawBytes(zf, maxEntryRaw)
		if rerr != nil || len(raw) < zipcrypto.HeaderLen {
			out = append(out, res)
			continue
		}
		k := start // value copy; Decrypt mutates the key state and the buffer
		full := append([]byte(nil), raw...)
		k.Decrypt(full)
		plain, derr := decompress(full[zipcrypto.HeaderLen:], zf.Method)
		if derr != nil || crc32.ChecksumIEEE(plain) != zf.CRC32 {
			out = append(out, res) // wrong state or not ZipCrypto under this key
			continue
		}
		res.Plaintext, res.OK = plain, true
		out = append(out, res)
	}
	return out, nil
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
