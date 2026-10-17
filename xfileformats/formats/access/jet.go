package access

import (
	"encoding/binary"
	"math"
	"unicode/utf16"
)

// The Jet (.mdb) database password is not cracked — it is read straight out of
// the header, because Jet stores it XOR-obfuscated with fixed, public material:
//
//  1. The header page is masked from offset 24 with a fixed 128-byte mask
//     (baseHeaderMask). jackcess/Access de-obfuscate it on read; Jet4 uses all
//     128 bytes, Jet3 the first 126.
//  2. Jet4 additionally masks the 40-byte password field (offset 66) with a
//     4-byte value folded from the database creation date: the 8 bytes at
//     offset 114 are an IEEE-754 little-endian double, truncated to an int32
//     and written little-endian; that 4-byte pattern repeats across the field.
//     Jet3 has no creation-date field and so no second mask.
//  3. The de-masked field is the password — UTF-16LE for Jet4, the single-byte
//     charset for Jet3 — NUL-terminated.
//
// Reversing (1)–(3) recovers the password with no search whatsoever. ACE
// (.accdb, Access 2007+) is NOT handled here: it uses a real Office-style
// RC4/AES KDF with no such shortcut. The decode is cross-validated against
// jackcess (an independent implementation) in jet_test.go.

const (
	jetMaskedHeaderOff = 24  // header obfuscation starts here
	jet4PasswordOff    = 66  // OFFSET_PASSWORD (Jet3 and Jet4)
	jet4PasswordSize   = 40  // SIZE_PASSWORD (Jet4)
	jet3PasswordSize   = 20  // SIZE_PASSWORD (Jet3)
	jet4HeaderDateOff  = 114 // OFFSET_HEADER_DATE (Jet4 only)
	jet4HeaderDateSize = 8
)

// baseHeaderMask is the fixed 128-byte XOR mask Jet applies to the header page
// from jetMaskedHeaderOff. Jet4 uses all 128 bytes; Jet3 uses the first 126.
var baseHeaderMask = []byte{
	0xb5, 0x6f, 0x03, 0x62, 0x61, 0x08, 0xc2, 0x55, 0xeb, 0xa9, 0x67, 0x72, 0x43, 0x3f, 0x00, 0x9c,
	0x7a, 0x9f, 0x90, 0xff, 0x80, 0x9a, 0x31, 0xc5, 0x79, 0xba, 0xed, 0x30, 0xbc, 0xdf, 0xcc, 0x9d,
	0x63, 0xd9, 0xe4, 0xc3, 0x7b, 0x42, 0xfb, 0x8a, 0xbc, 0x4e, 0x86, 0xfb, 0xec, 0x37, 0x5d, 0x44,
	0x9c, 0xfa, 0xc6, 0x5e, 0x28, 0xe6, 0x13, 0xb6, 0x8a, 0x60, 0x54, 0x94, 0x7b, 0x36, 0xf5, 0x72,
	0xdf, 0xb1, 0x77, 0xf4, 0x13, 0x43, 0xcf, 0xaf, 0xb1, 0x33, 0x34, 0x61, 0x79, 0x5b, 0x92, 0xb5,
	0x7c, 0x2a, 0x05, 0xf1, 0x7c, 0x99, 0x01, 0x1b, 0x98, 0xfd, 0x12, 0x4f, 0x4a, 0x94, 0x6c, 0x3e,
	0x60, 0x26, 0x5f, 0x95, 0xf8, 0xd0, 0x89, 0x24, 0x85, 0x67, 0xc6, 0x1f, 0x27, 0x44, 0xd2, 0xee,
	0xcf, 0x65, 0xed, 0xff, 0x07, 0xc7, 0x46, 0xa1, 0x78, 0x16, 0x0c, 0xed, 0xe9, 0x2d, 0x62, 0xd4,
}

// RecoverResult reports a Jet database-password recovery.
type RecoverResult struct {
	Variant     string // "jet3" or "jet4"
	HasPassword bool   // false => the database has no password set
	Password    string // the recovered password (empty when HasPassword is false)
}

// RecoverJetPassword decodes the database password straight out of a Jet
// (.mdb) header, with no cracking. It returns ok=false if the buffer is not a
// supported Jet header (too short, not Jet, or ACE). A supported header with no
// password set returns ok=true and HasPassword=false.
func RecoverJetPassword(header []byte) (RecoverResult, bool) {
	variant := Variant(header)
	if variant != "jet3" && variant != "jet4" {
		return RecoverResult{}, false // not Jet, or ACE (no header-XOR shortcut)
	}
	// Re-check the signature so a caller passing arbitrary bytes can't slip a
	// non-Jet buffer past the version byte alone.
	if conf, ok := New().Detect(header); !ok || conf == 0 {
		return RecoverResult{}, false
	}

	pwSize := jet4PasswordSize
	maskLen := len(baseHeaderMask)
	if variant == "jet3" {
		pwSize = jet3PasswordSize
		maskLen = len(baseHeaderMask) - 2
	}
	if len(header) < jet4PasswordOff+pwSize {
		return RecoverResult{}, false
	}

	// De-obfuscate the password field (and, for Jet4, the date field) using the
	// fixed header mask. demask reverses step (1) for a single absolute offset.
	demask := func(off int) byte {
		b := header[off]
		if mi := off - jetMaskedHeaderOff; mi >= 0 && mi < maskLen {
			b ^= baseHeaderMask[mi]
		}
		return b
	}

	field := make([]byte, pwSize)
	for i := range field {
		field[i] = demask(jet4PasswordOff + i)
	}

	// Jet4: fold the creation date into a 4-byte mask and strip it (step 2).
	if variant == "jet4" && len(header) >= jet4HeaderDateOff+jet4HeaderDateSize {
		var dateBytes [8]byte
		for i := range dateBytes {
			dateBytes[i] = demask(jet4HeaderDateOff + i)
		}
		dateVal := math.Float64frombits(binary.LittleEndian.Uint64(dateBytes[:]))
		var mask [4]byte
		binary.LittleEndian.PutUint32(mask[:], uint32(int32(dateVal)))
		for i := range field {
			field[i] ^= mask[i%4]
		}
	}

	res := RecoverResult{Variant: variant}
	res.Password = decodeJetPassword(field, variant)
	res.HasPassword = res.Password != ""
	return res, true
}

// decodeJetPassword turns a de-masked password field into a string, trimming at
// the first NUL. Jet4 is UTF-16LE; Jet3 is the single-byte charset (treated as
// Latin-1, which is byte-for-byte for ASCII passwords).
func decodeJetPassword(field []byte, variant string) string {
	if variant == "jet4" {
		u16 := make([]uint16, 0, len(field)/2)
		for i := 0; i+1 < len(field); i += 2 {
			c := binary.LittleEndian.Uint16(field[i : i+2])
			if c == 0 {
				break
			}
			u16 = append(u16, c)
		}
		return string(utf16.Decode(u16))
	}
	runes := make([]rune, 0, len(field))
	for _, b := range field {
		if b == 0 {
			break
		}
		runes = append(runes, rune(b))
	}
	return string(runes)
}
