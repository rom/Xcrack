package archive

import (
	"io"

	"github.com/nwaples/rardecode/v2"
	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/rar5"
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
	// RAR5 stores an 8-byte password-check value in its (unencrypted) crypt
	// record, so a wrong password can be rejected after key derivation alone — no
	// decrypt, no decompress. Parse it once; RAR uses one password for the whole
	// archive, so the same fast verifier serves every encrypted entry. RAR4 and
	// any parse failure fall back to the decrypt-and-check verifier below.
	cryptParams, hasFast := parseRAR5Crypt(r, size)
	fastVerify := func(pw []byte) (bool, error) { return rar5.Verify(string(pw), cryptParams), nil }

	rr, err := rardecode.NewReader(section(r, size))
	if err != nil {
		// Encrypted headers (rar -hp) hide the listing; offer a gated entry. With a
		// parsed RAR5 crypt header the gate uses the fast check value instead of a
		// trial decryption of the hidden headers.
		verify := rarHdrVerify(r, size)
		if hasFast {
			verify = fastVerify
		}
		e := gatedEntry("rar-aes-header", verify, rarHdrTar(r, size))
		if hasFast {
			e.Challenge = rar5Challenge(cryptParams)
		}
		return []*xfileformats.Entry{e}, nil
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
			if hasFast {
				e.Challenge = rar5Challenge(cryptParams)
				e.Verify = fastVerify
			} else {
				e.Challenge = &xcrypto.Challenge{Scheme: "rar-aes", Cipher: xcrypto.CipherSpec{Algo: "aes-cbc"}}
				e.Verify = func(pw []byte) (bool, error) { return rarVerify(r, size, fn, string(pw)) }
			}
			e.Open = func(pw []byte) (io.Reader, error) { return rarOpen(r, size, fn, string(pw)) }
		} else {
			e.Open = func([]byte) (io.Reader, error) { return rarOpen(r, size, fn, "") }
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// rarHdrVerify returns a verifier for a header-encrypted rar.
func rarHdrVerify(r io.ReaderAt, size int64) func(pw []byte) (bool, error) {
	return func(pw []byte) (bool, error) {
		rr, err := rardecode.NewReader(section(r, size), rardecode.Password(string(pw)))
		if err != nil {
			return false, nil
		}
		hdr, err := rr.Next()
		if err != nil {
			return err == io.EOF, nil // decrypted header, possibly empty archive
		}
		_ = hdr
		return true, nil
	}
}

// rarHdrTar returns an opener that repacks a header-encrypted rar's members as tar.
func rarHdrTar(r io.ReaderAt, size int64) func(pw []byte) ([]byte, error) {
	return func(pw []byte) ([]byte, error) {
		rr, err := rardecode.NewReader(section(r, size), rardecode.Password(string(pw)))
		if err != nil {
			return nil, xcrypto.ErrWrongPassword
		}
		var members []packMember
		for len(members) < maxEntries {
			hdr, err := rr.Next()
			if err != nil {
				break
			}
			if hdr.IsDir {
				continue
			}
			name := sanitize(hdr.Name)
			if name == "" {
				continue
			}
			b, rerr := io.ReadAll(io.LimitReader(rr, maxDecompressed))
			if rerr != nil {
				return nil, rerr
			}
			members = append(members, packMember{name: name, data: b})
		}
		return packTar(members)
	}
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
