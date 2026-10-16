package archive

import (
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
	rd, err := sevenzip.NewReaderWithPassword(r, size, "")
	if err != nil {
		// The header is encrypted (or the archive is invalid); offer a gated entry.
		return []*xfileformats.Entry{gatedEntry("7z-aes256-header", szHdrVerify(r, size), szHdrTar(r, size))}, nil
	}
	// probe whether content is encrypted (uniform for `7z a -p`): opening without
	// a password may succeed lazily, so actually attempt to read a byte.
	encrypted := false
	for _, f := range rd.File {
		if szIsDir(f) {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			encrypted = true
		} else {
			if _, rerr := io.Copy(io.Discard, io.LimitReader(rc, 1)); rerr != nil {
				encrypted = true
			}
			rc.Close()
		}
		break
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

// szHdrVerify returns a verifier for a header-encrypted 7z: the password opens
// the archive and the first member reads cleanly.
func szHdrVerify(r io.ReaderAt, size int64) func(pw []byte) (bool, error) {
	return func(pw []byte) (bool, error) {
		rd, err := sevenzip.NewReaderWithPassword(r, size, string(pw))
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
		rd, err := sevenzip.NewReaderWithPassword(r, size, string(pw))
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
	rd, err := sevenzip.NewReaderWithPassword(r, size, pw)
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

// szVerify authoritatively checks a password by fully reading the entry (7z
// validates the CRC at end-of-stream), streaming to discard so it stays
// memory-bounded.
func szVerify(r io.ReaderAt, size int64, name, pw string) (bool, error) {
	rd, err := sevenzip.NewReaderWithPassword(r, size, pw)
	if err != nil {
		return false, nil
	}
	for _, f := range rd.File {
		if f.Name == name && !szIsDir(f) {
			rc, err := f.Open()
			if err != nil {
				return false, nil
			}
			_, rerr := io.Copy(io.Discard, io.LimitReader(rc, maxDecompressed))
			rc.Close()
			return rerr == nil, nil
		}
	}
	return false, nil
}
