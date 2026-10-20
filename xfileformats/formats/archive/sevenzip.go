package archive

import (
	"errors"
	"hash/crc32"
	"io"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/rom/xcrypto"
	"github.com/rom/xfileformats"
)

type sevenzipFormat struct{}

func (sevenzipFormat) Name() string            { return "7z" }
func (sevenzipFormat) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

func (sevenzipFormat) Detect(p []byte) (float64, bool) {
	if len(p) >= 6 && p[0] == '7' && p[1] == 'z' && p[2] == 0xbc && p[3] == 0xaf && p[4] == 0x27 && p[5] == 0x1c {
		return 0.9, true
	}
	return 0, false
}

func szIsDir(f *sevenzip.File) bool {
	return f.Attributes&0x10 != 0 || strings.HasSuffix(f.Name, "/")
}

// Entries lists a 7z archive. Content-encrypted archives (plaintext headers)
// are enumerated with per-entry encryption; a header-encrypted archive (names
// hidden) becomes a single password-gated entry whose Open repacks the
// decrypted members as a tar.
func (sevenzipFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	rd, err := szNewReader(r, size, "")
	if err != nil {
		if errors.Is(err, errSzOversizeHeader) {
			// The header declares impossibly much structure (a memory-DoS attempt);
			// refuse it rather than allocate. See szWithinSize.
			return nil, xfileformats.ErrMalformed
		}
		// The header is encrypted (or the archive is invalid); offer a gated entry.
		return []*xfileformats.Entry{gatedEntry("7z-aes256-header", szHdrVerify(r, size), szHdrTar(r, size))}, nil
	}
	// Probe whether content is encrypted (uniform for `7z a -p`): the smallest
	// member must decode and match its stored CRC under the empty password, else
	// it is password-gated. See szReadOK.
	encrypted := false
	if name := szSmallestMember(rd); name != "" {
		encrypted = !szReadOK(r, size, name, "")
	}
	var entries []*xfileformats.Entry
	for _, f := range rd.File {
		if szIsDir(f) || len(entries) >= maxEntries {
			continue
		}
		name := sanitize(f.Name)
		if name == "" {
			continue
		}
		fn := f.Name
		e := &xfileformats.Entry{Path: name, Size: int64(f.UncompressedSize)}
		if encrypted {
			e.Encrypted = true
			e.Challenge = &xcrypto.Challenge{Scheme: "7z-aes256", Cipher: xcrypto.CipherSpec{Algo: "aes-cbc", KeyBits: 256}}
			e.Verify = func(pw []byte) (bool, error) { return szVerify(r, size, fn, string(pw)) }
			e.Open = func(pw []byte) (io.Reader, error) { return szOpen(r, size, fn, string(pw)) }
		} else {
			e.Open = func([]byte) (io.Reader, error) { return szOpen(r, size, fn, "") }
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// szSmallestMember returns the name of the smallest non-empty, non-directory
// member — the cheapest to decode-and-CRC when probing/verifying a password —
// or "" when the archive has none. In a `7z a -p` archive every member shares
// one encrypted folder, so any member settles whether content is encrypted.
func szSmallestMember(rd *sevenzip.Reader) string {
	name := ""
	var best uint64
	for _, f := range rd.File {
		if szIsDir(f) || f.UncompressedSize == 0 {
			continue
		}
		if name == "" || f.UncompressedSize < best {
			name, best = f.Name, f.UncompressedSize
		}
	}
	return name
}

// szReadOK reports whether member `name` decrypts and decompresses cleanly under
// pw. 7z content encryption has no password MAC, and a wrong password yields
// garbage that can still "decode" without error — especially for short or stored
// members, and varying with the per-archive random AES IV — so a clean read is
// not proof on its own (this made a naive read-probe flaky). The authoritative
// check is the member's stored CRC32: recompute it over the decoded bytes and
// require a match. A member with no stored CRC (CRC32 == 0) or one larger than
// the decompression backstop cannot be CRC-verified, so there we fall back to
// "decoded without error".
func szReadOK(r io.ReaderAt, size int64, name, pw string) bool {
	rd, err := szNewReader(r, size, pw)
	if err != nil {
		return false
	}
	for _, f := range rd.File {
		if f.Name != name || szIsDir(f) {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			return false
		}
		h := crc32.NewIEEE()
		_, rerr := io.Copy(h, io.LimitReader(rc, maxDecompressed))
		rc.Close()
		if rerr != nil {
			return false
		}
		if f.CRC32 == 0 || f.UncompressedSize > uint64(maxDecompressed) {
			return true // cannot CRC-verify; the clean decode is the best signal
		}
		return h.Sum32() == f.CRC32
	}
	return false
}

// szHdrVerify returns a verifier for a header-encrypted 7z: the password opens
// the archive and the first member reads cleanly.
func szHdrVerify(r io.ReaderAt, size int64) func(pw []byte) (bool, error) {
	return func(pw []byte) (bool, error) {
		rd, err := szNewReader(r, size, string(pw))
		if err != nil {
			return false, nil
		}
		for _, f := range rd.File {
			if szIsDir(f) {
				continue
			}
			rc, oerr := f.Open()
			if oerr != nil {
				return false, nil
			}
			_, rerr := io.Copy(io.Discard, io.LimitReader(rc, 1))
			rc.Close()
			return rerr == nil, nil
		}
		return true, nil // header decrypted; archive has no files
	}
}

// szHdrTar returns an opener that repacks a header-encrypted 7z's members as tar.
func szHdrTar(r io.ReaderAt, size int64) func(pw []byte) ([]byte, error) {
	return func(pw []byte) ([]byte, error) {
		rd, err := szNewReader(r, size, string(pw))
		if err != nil {
			return nil, xcrypto.ErrWrongPassword
		}
		var members []packMember
		for _, f := range rd.File {
			if szIsDir(f) || len(members) >= maxEntries {
				continue
			}
			name := sanitize(f.Name)
			if name == "" {
				continue
			}
			rc, oerr := f.Open()
			if oerr != nil {
				return nil, xcrypto.ErrWrongPassword
			}
			b, rerr := io.ReadAll(io.LimitReader(rc, maxDecompressed))
			rc.Close()
			if rerr != nil {
				return nil, rerr
			}
			members = append(members, packMember{name: name, data: b})
		}
		return packTar(members)
	}
}

func szOpen(r io.ReaderAt, size int64, name, pw string) (io.Reader, error) {
	rd, err := szNewReader(r, size, pw)
	if err != nil {
		return nil, xcrypto.ErrWrongPassword
	}
	for _, f := range rd.File {
		if f.Name == name && !szIsDir(f) {
			rc, err := f.Open()
			if err != nil {
				return nil, xcrypto.ErrWrongPassword
			}
			return io.LimitReader(rc, maxDecompressed), nil
		}
	}
	return nil, xfileformats.ErrMalformed
}

// szVerify authoritatively checks a password by fully reading the entry and
// matching its stored CRC32 (see szReadOK), streaming to a hash so it stays
// memory-bounded. The library does not check the per-member CRC itself, so
// without this a wrong password whose garbage happens to decode is wrongly
// accepted.
func szVerify(r io.ReaderAt, size int64, name, pw string) (bool, error) {
	return szReadOK(r, size, name, pw), nil
}
