package access

import (
	"encoding/binary"
	"math"
	"testing"
	"unicode/utf16"
)

// buildJet4Header constructs a Jet4 header carrying password pw masked exactly
// as a real file would be: the UTF-16LE field gets the creation-date mask, then
// the whole header region gets baseHeaderMask. It is the inverse of
// RecoverJetPassword, used to round-trip the decoder independently of the
// jackcess fixture.
func buildJet4Header(t *testing.T, pw string, date float64) []byte {
	t.Helper()
	h := make([]byte, 160)
	copy(h[4:], []byte("Standard Jet DB"))
	h[headerVersionOffset] = 0x01

	// UTF-16LE password field (40 bytes, zero-padded).
	field := make([]byte, jet4PasswordSize)
	u16 := utf16.Encode([]rune(pw))
	for i, c := range u16 {
		if 2*i+1 >= len(field) {
			t.Fatalf("password %q too long for the field", pw)
		}
		binary.LittleEndian.PutUint16(field[2*i:], c)
	}
	// Creation-date mask (step 2), plaintext date at its offset.
	binary.LittleEndian.PutUint64(h[jet4HeaderDateOff:], math.Float64bits(date))
	var mask [4]byte
	binary.LittleEndian.PutUint32(mask[:], uint32(int32(date)))
	for i := range field {
		field[i] ^= mask[i%4]
	}
	copy(h[jet4PasswordOff:], field)

	// Outer header mask (step 1) over [24, 24+128).
	for i, m := range baseHeaderMask {
		h[jetMaskedHeaderOff+i] ^= m
	}
	return h
}

// jet4Fixture is the first 160 bytes of a real Jet4 (.mdb, Access 2000) file
// created by jackcess (an independent implementation) with the database
// password "SecretJet4!pass", via:
//
//	Database db = new DatabaseBuilder(f).setFileFormat(V2000).create();
//	... add a table and row ...
//	PasswordUtil.setDatabasePassword(db, "SecretJet4!pass");
//
// jackcess re-opens the file with that password successfully, so the header is
// a genuine, correctly-masked Jet4 password field. Decoding it back to the
// known password cross-validates RecoverJetPassword against jackcess end to end
// (header XOR mask + creation-date mask + UTF-16LE), with no cracking.
var jet4Fixture = []byte{
	0x00, 0x01, 0x00, 0x00, 0x53, 0x74, 0x61, 0x6e, 0x64, 0x61, 0x72, 0x64, 0x20, 0x4a, 0x65, 0x74,
	0x20, 0x44, 0x42, 0x00, 0x01, 0x00, 0x00, 0x00, 0xb5, 0x6e, 0x03, 0x62, 0x60, 0x09, 0xc2, 0x55,
	0xe9, 0xa9, 0x67, 0x72, 0x40, 0x3f, 0x00, 0x9c, 0x7e, 0x9f, 0x90, 0xff, 0x85, 0x9a, 0x31, 0xc5,
	0x79, 0xba, 0xed, 0x30, 0xbc, 0xdf, 0xcc, 0x9d, 0x63, 0xd9, 0xe4, 0xc3, 0x9f, 0x46, 0xfb, 0x8a,
	0xbc, 0x4e, 0x2a, 0x6f, 0x89, 0x37, 0xc1, 0xd0, 0xee, 0xfa, 0x5c, 0xca, 0x5c, 0xe6, 0xa6, 0x22,
	0xef, 0x60, 0xdf, 0x00, 0x4f, 0x36, 0x2b, 0xe6, 0xaf, 0xb1, 0xe9, 0x60, 0x60, 0x43, 0x43, 0x3b,
	0xb1, 0x33, 0xcb, 0xf5, 0x79, 0x5b, 0x6d, 0x21, 0x7c, 0x2a, 0xaf, 0xd0, 0x7c, 0x99, 0x08, 0x1f,
	0x98, 0xfd, 0xae, 0x3d, 0x55, 0xe9, 0x9d, 0xa1, 0x82, 0x66, 0x5f, 0x95, 0xf8, 0xd0, 0x89, 0x24,
	0x85, 0x67, 0xc6, 0x1f, 0x27, 0x44, 0xd2, 0xee, 0xcf, 0x65, 0xed, 0xff, 0x07, 0xc7, 0x46, 0xa1,
	0x78, 0x16, 0x0c, 0xed, 0xe9, 0x2d, 0x62, 0xd4, 0x54, 0x06, 0x00, 0x00, 0x34, 0x2e, 0x30, 0x00,
}

// buildJet3Header constructs a Jet3 header for pw. Jet3 has no creation-date
// mask and a single-byte charset, so the (ASCII) password sits directly in the
// field under only the fixed header mask (its first 126 bytes).
func buildJet3Header(t *testing.T, pw string) []byte {
	t.Helper()
	h := make([]byte, 160)
	copy(h[4:], []byte("Standard Jet DB"))
	h[headerVersionOffset] = 0x00

	field := make([]byte, jet3PasswordSize)
	if len(pw) > len(field) {
		t.Fatalf("password %q too long for the Jet3 field", pw)
	}
	copy(field, []byte(pw))
	copy(h[jet4PasswordOff:], field)

	for i := 0; i < len(baseHeaderMask)-2; i++ {
		h[jetMaskedHeaderOff+i] ^= baseHeaderMask[i]
	}
	return h
}

func TestRecoverJet3PasswordRoundTrip(t *testing.T) {
	for _, pw := range []string{"", "jet3pw", "ACCESS97"} {
		hdr := buildJet3Header(t, pw)
		res, ok := RecoverJetPassword(hdr)
		if !ok || res.Variant != "jet3" {
			t.Fatalf("pw=%q: ok=%v variant=%q", pw, ok, res.Variant)
		}
		if res.Password != pw || res.HasPassword != (pw != "") {
			t.Fatalf("pw=%q: recovered %q hasPassword=%v", pw, res.Password, res.HasPassword)
		}
	}
}

func TestRecoverJetPasswordQPDFVectorJackcess(t *testing.T) {
	res, ok := RecoverJetPassword(jet4Fixture)
	if !ok {
		t.Fatal("RecoverJetPassword returned ok=false for a real Jet4 header")
	}
	if res.Variant != "jet4" {
		t.Fatalf("variant = %q, want jet4", res.Variant)
	}
	if !res.HasPassword {
		t.Fatal("HasPassword = false, want true")
	}
	if res.Password != "SecretJet4!pass" {
		t.Fatalf("recovered password = %q, want %q", res.Password, "SecretJet4!pass")
	}
}

// TestRecoverJetPasswordRejectsACE confirms ACE (.accdb) is declined — its
// scheme has no header-XOR shortcut.
func TestRecoverJetPasswordRejectsACE(t *testing.T) {
	ace := make([]byte, 160)
	copy(ace[4:], []byte("Standard ACE DB"))
	ace[headerVersionOffset] = 0x02
	if _, ok := RecoverJetPassword(ace); ok {
		t.Fatal("RecoverJetPassword accepted an ACE header")
	}
}

// TestRecoverJetPasswordRejectsNonJet confirms non-Jet buffers are declined.
func TestRecoverJetPasswordRejectsNonJet(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		make([]byte, 8),
		append([]byte("PK\x03\x04"), make([]byte, 160)...),
	} {
		if _, ok := RecoverJetPassword(b); ok {
			t.Fatalf("RecoverJetPassword accepted a non-Jet buffer of len %d", len(b))
		}
	}
}

// TestRecoverJetPasswordRoundTrip builds a Jet4-shaped header for a chosen
// password with the same two masks and confirms RecoverJetPassword inverts it,
// exercising the decoder independently of the jackcess fixture (several
// passwords, including non-ASCII and empty).
func TestRecoverJetPasswordRoundTrip(t *testing.T) {
	for _, pw := range []string{"", "p", "hunter2", "a longer one 123!", "café-Ω"} {
		hdr := buildJet4Header(t, pw, 45000.25)
		res, ok := RecoverJetPassword(hdr)
		if !ok || res.Variant != "jet4" {
			t.Fatalf("pw=%q: ok=%v variant=%q", pw, ok, res.Variant)
		}
		if res.Password != pw {
			t.Fatalf("pw=%q: recovered %q", pw, res.Password)
		}
		if res.HasPassword != (pw != "") {
			t.Fatalf("pw=%q: HasPassword=%v", pw, res.HasPassword)
		}
	}
}
