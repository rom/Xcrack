package archive

import (
	"io"

	"github.com/nwaples/rardecode/v2"
	"github.com/rom/xcrypto"
	"github.com/rom/xfileformats"
)

type rarFormat struct{}

func (rarFormat) Name() string            { return "rar" }
func (rarFormat) Caps() xfileformats.Caps { return xfileformats.Caps{Container: true} }

func (rarFormat) Detect(p []byte) (float64, bool) {
	if len(p) >= 7 && string(p[:7]) == "Rar!\x1a\x07\x00" { // RAR 4.x
		return 0.9, true
	}
	if len(p) >= 8 && string(p[:8]) == "Rar!\x1a\x07\x01\x00" { // RAR 5.x
		return 0.9, true
	}
	return 0, false
}

func (rarFormat) Entries(r io.ReaderAt, size int64) ([]*xfileformats.Entry, error) {
	rr, err := rardecode.NewReader(section(r, size))
	if err != nil {
		return nil, xfileformats.ErrUnsupported // header-encrypted or invalid
	}
	var entries []*xfileformats.Entry
	for len(entries) < maxEntries {
		hdr, err := rr.Next()
		if err != nil {
			break // EOF, truncation, or header-encrypted
		}
		if hdr.IsDir {
			continue
		}
		name := sanitize(hdr.Name)
		if name == "" {
			continue
		}
		fn := hdr.Name
		e := &xfileformats.Entry{Path: name, Size: hdr.UnPackedSize}
		if hdr.Encrypted {
			e.Encrypted = true
			e.Challenge = &xcrypto.Challenge{Scheme: "rar-aes", Cipher: xcrypto.CipherSpec{Algo: "aes-cbc"}}
			e.Verify = func(pw []byte) (bool, error) { return rarVerify(r, size, fn, string(pw)) }
			e.Open = func(pw []byte) (io.Reader, error) { return rarOpen(r, size, fn, string(pw)) }
		} else {
			e.Open = func([]byte) (io.Reader, error) { return rarOpen(r, size, fn, "") }
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func rarOpen(r io.ReaderAt, size int64, name, pw string) (io.Reader, error) {
	rr, err := rardecode.NewReader(section(r, size), rardecode.Password(pw))
	if err != nil {
		return nil, xcrypto.ErrWrongPassword
	}
	for {
		hdr, err := rr.Next()
		if err != nil {
			return nil, xfileformats.ErrMalformed
		}
		if hdr.Name == name && !hdr.IsDir {
			return io.LimitReader(rr, maxDecompressed), nil
		}
	}
}

func rarVerify(r io.ReaderAt, size int64, name, pw string) (bool, error) {
	rr, err := rardecode.NewReader(section(r, size), rardecode.Password(pw))
	if err != nil {
		return false, nil
	}
	for {
		hdr, err := rr.Next()
		if err != nil {
			return false, nil
		}
		if hdr.Name == name && !hdr.IsDir {
			_, rerr := io.Copy(io.Discard, io.LimitReader(rr, maxDecompressed))
			return rerr == nil, nil
		}
	}
}
