package candidates

import (
	"fmt"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// LengthFilter wraps src to drop candidates whose length (in characters, i.e.
// decoded UTF-8 runes) falls outside [minLen, maxLen]. minLen <= 0 means no
// lower bound; maxLen <= 0 means no upper bound. It is applied to the natural
// (UTF-8) candidate, before any Encode transcoding, so the bounds mean what a
// user typing a password would expect. Invalid UTF-8 is measured by byte length.
func LengthFilter(src Source, minLen, maxLen int) Source {
	if src == nil || (minLen <= 0 && maxLen <= 0) {
		return src
	}
	return &lengthFilter{src: src, min: minLen, max: maxLen}
}

type lengthFilter struct {
	src      Source
	min, max int
}

func (f *lengthFilter) Next() ([]byte, error) {
	for {
		b, err := f.src.Next()
		if err != nil {
			return nil, err
		}
		n := utf8.RuneCount(b)
		if f.min > 0 && n < f.min {
			continue
		}
		if f.max > 0 && n > f.max {
			continue
		}
		return b, nil
	}
}

// Len is -1: filtering makes the surviving count non-trivial to know up front.
func (f *lengthFilter) Len() int64   { return -1 }
func (f *lengthFilter) Reset() error { return f.src.Reset() }

func (f *lengthFilter) CloneSource() Source {
	if c, ok := f.src.(Cloner); ok {
		if cs := c.CloneSource(); cs != nil {
			return &lengthFilter{src: cs, min: f.min, max: f.max}
		}
	}
	return nil
}

// Encoding identifies a byte encoding a candidate is transcoded to before it is
// tested, for schemes or wordlists whose passwords are not UTF-8.
type Encoding int

const (
	EncUTF8    Encoding = iota // identity (the native wordlist encoding)
	EncLatin1                  // ISO-8859-1 / Latin-1: one byte per rune < 256
	EncUTF16LE                 // UTF-16, little-endian
	EncUTF16BE                 // UTF-16, big-endian
)

// ParseEncoding maps an encoding name to an Encoding. Accepted: "utf-8"/"utf8"
// (default), "latin1"/"iso-8859-1", "utf-16le"/"utf16le", "utf-16be"/"utf16be".
func ParseEncoding(name string) (Encoding, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "utf-8", "utf8":
		return EncUTF8, nil
	case "latin1", "latin-1", "iso-8859-1", "iso8859-1", "cp819":
		return EncLatin1, nil
	case "utf-16le", "utf16le", "utf-16", "utf16":
		return EncUTF16LE, nil
	case "utf-16be", "utf16be":
		return EncUTF16BE, nil
	default:
		return EncUTF8, fmt.Errorf("unknown encoding %q (want utf-8, latin1, utf-16le, utf-16be)", name)
	}
}

// Encode wraps src to transcode each candidate from UTF-8 to enc before it is
// tested. EncUTF8 returns src unchanged. A candidate that the target cannot
// represent (a rune >= 256 under Latin-1) is dropped rather than mangled. This
// is for passwords originally typed in a legacy single-byte code page or needed
// as raw UTF-16; it is distinct from a scheme's own internal encoding (e.g. the
// Office RC4 schedule already UTF-16LE-encodes the password, so do not also
// transcode to UTF-16 there).
func Encode(src Source, enc Encoding) Source {
	if src == nil || enc == EncUTF8 {
		return src
	}
	return &encodeSource{src: src, enc: enc}
}

type encodeSource struct {
	src Source
	enc Encoding
}

func (e *encodeSource) Next() ([]byte, error) {
	for {
		b, err := e.src.Next()
		if err != nil {
			return nil, err
		}
		out, ok := transcode(b, e.enc)
		if !ok {
			continue // unrepresentable in the target encoding
		}
		return out, nil
	}
}

func (e *encodeSource) Len() int64   { return e.src.Len() }
func (e *encodeSource) Reset() error { return e.src.Reset() }

func (e *encodeSource) CloneSource() Source {
	if c, ok := e.src.(Cloner); ok {
		if cs := c.CloneSource(); cs != nil {
			return &encodeSource{src: cs, enc: e.enc}
		}
	}
	return nil
}

// transcode converts a UTF-8 candidate to enc. ok is false when a rune cannot
// be represented (Latin-1 only).
func transcode(b []byte, enc Encoding) (out []byte, ok bool) {
	switch enc {
	case EncLatin1:
		out = make([]byte, 0, len(b))
		for i := 0; i < len(b); {
			r, size := utf8.DecodeRune(b[i:])
			if r == utf8.RuneError && size == 1 {
				out = append(out, b[i]) // pass raw byte through
				i++
				continue
			}
			if r > 0xFF {
				return nil, false
			}
			out = append(out, byte(r))
			i += size
		}
		return out, true
	case EncUTF16LE, EncUTF16BE:
		units := utf16.Encode([]rune(string(b)))
		out = make([]byte, 0, len(units)*2)
		for _, u := range units {
			if enc == EncUTF16LE {
				out = append(out, byte(u), byte(u>>8))
			} else {
				out = append(out, byte(u>>8), byte(u))
			}
		}
		return out, true
	default:
		return append([]byte(nil), b...), true
	}
}
