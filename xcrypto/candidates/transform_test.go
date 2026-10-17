package candidates

import (
	"bytes"
	"testing"
)

func drainSrc(t *testing.T, s Source) [][]byte {
	t.Helper()
	var out [][]byte
	for {
		b, err := s.Next()
		if err != nil {
			return out
		}
		out = append(out, append([]byte(nil), b...))
	}
}

func TestLengthFilter(t *testing.T) {
	// "é" is 2 bytes but 1 rune; the filter counts runes.
	in := func() Source { return Explicit("a", "abc", "abcd", "abcde", "é", "ébc") }
	got := drainSrc(t, LengthFilter(in(), 2, 3))
	want := []string{"abc", "ébc"}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates %q, want %v", len(got), bytesToStr(got), want)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	// No-op passthrough when both bounds are zero.
	if LengthFilter(in(), 0, 0) == nil {
		t.Fatal("zero bounds should return the source unchanged, not nil")
	}
	all := drainSrc(t, LengthFilter(in(), 0, 0))
	if len(all) != 6 {
		t.Fatalf("passthrough yielded %d, want 6", len(all))
	}
}

func TestEncodeLatin1(t *testing.T) {
	src := Encode(Explicit("café", "señor", "€uro"), EncLatin1) // € (U+20AC) is unrepresentable
	got := drainSrc(t, src)
	// "café" -> 63 61 66 E9 ; "señor" -> ... F1 ... ; "€uro" dropped.
	want := [][]byte{
		{0x63, 0x61, 0x66, 0xE9},
		{0x73, 0x65, 0xF1, 0x6F, 0x72},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d, want %d (%x)", len(got), len(want), got)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("[%d] = %x, want %x", i, got[i], want[i])
		}
	}
}

func TestEncodeUTF16(t *testing.T) {
	le := drainSrc(t, Encode(Explicit("AB"), EncUTF16LE))
	if len(le) != 1 || !bytes.Equal(le[0], []byte{0x41, 0x00, 0x42, 0x00}) {
		t.Fatalf("utf-16le(AB) = %x, want 41004200", le)
	}
	be := drainSrc(t, Encode(Explicit("AB"), EncUTF16BE))
	if len(be) != 1 || !bytes.Equal(be[0], []byte{0x00, 0x41, 0x00, 0x42}) {
		t.Fatalf("utf-16be(AB) = %x, want 00410042", be)
	}
	// A rune outside the BMP becomes a surrogate pair (4 bytes).
	em := drainSrc(t, Encode(Explicit("\U0001F600"), EncUTF16LE)) // 😀
	if len(em) != 1 || len(em[0]) != 4 {
		t.Fatalf("utf-16le(emoji) = %x, want a 4-byte surrogate pair", em)
	}
}

func TestParseEncoding(t *testing.T) {
	for _, c := range []struct {
		name string
		want Encoding
	}{
		{"", EncUTF8}, {"utf-8", EncUTF8}, {"latin1", EncLatin1},
		{"ISO-8859-1", EncLatin1}, {"utf-16le", EncUTF16LE}, {"UTF-16BE", EncUTF16BE},
	} {
		got, err := ParseEncoding(c.name)
		if err != nil || got != c.want {
			t.Errorf("ParseEncoding(%q) = (%v,%v), want (%v,nil)", c.name, got, err, c.want)
		}
	}
	if _, err := ParseEncoding("ebcdic"); err == nil {
		t.Error("unknown encoding should error")
	}
}

func bytesToStr(bs [][]byte) []string {
	out := make([]string, len(bs))
	for i, b := range bs {
		out[i] = string(b)
	}
	return out
}
