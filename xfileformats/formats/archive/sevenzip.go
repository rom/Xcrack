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

// Entries lists a 7z archive. Only content-encrypted archives (plaintext
// headers) are enumerable without a password; header-encrypted archives report
// unsupported.
func (sevenzipFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	rd, err := sevenzip.NewReaderWithPassword(r, size, "")
	if err != nil {
		return nil, xfileformats.ErrUnsupported // header-encrypted or invalid
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
