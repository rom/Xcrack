package vbaproject

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Golden fixtures produced by an INDEPENDENT Python reference implementation of
// the MS-OVBA Encryption algorithm (2.4.3.1) plus hashlib SHA-1 for the Password
// Hash (2.4.4.4) — research/vba_oracle.py. The SHA-1 digests are therefore
// cross-checked Python-hashlib vs Go-crypto/sha1, and the data-encryption
// transform is cross-checked against a second implementation. The algorithm
// (SHA1(password_MBCS || 4-byte salt), then MS-OVBA 2.4.3 obfuscation → hex DPB)
// is independently corroborated by Didier Stevens' "Cracking VBA Project
// Passwords" (John dynamic_24 / hashcat -m 110 --hex-salt).
type fixture struct {
	name     string
	dpb      string // hex (as it appears in the PROJECT stream DPB="..." field)
	password string
	keyHex   string // expected 4-byte salt (hashed cases)
	hashHex  string // expected 20-byte SHA-1 (hashed cases)
}

var hashedFixtures = []fixture{
	{"basic", "A7A59B3FD4528F6F8F6F7091906F9EA2F39131587C65CDA11B80ED7C56150B6088C3209822962A", "Welcome1", "11223344", "06cf7cb1e0e4aacb0bf7b23b9acf5271d9040608"},
	{"keynull", "1012457A627A62859B80657E27BE6AFE284312559138F194C1200AEC4E00FA7B4F12A54D", "s3cr3t!", "00410042", "fe407db7af509ddf83b56920acf8e4c8b3e24f3b"},
	{"hashnull", "FEFCFF5712DEC3FBC3FB3C01C8F7883F981A34147BC9DA62C94E74237A0AA512F0B199BC7D3547", "nullseek2", "3711005a", "c6f453aef3de719d1243cdfad1c99e0068a543ca"},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestParseHashedFixtures(t *testing.T) {
	for _, f := range hashedFixtures {
		t.Run(f.name, func(t *testing.T) {
			pw, err := ParseDPB(mustHex(t, f.dpb))
			if err != nil {
				t.Fatalf("ParseDPB: %v", err)
			}
			if pw.Kind != KindHash {
				t.Fatalf("Kind=%v, want KindHash", pw.Kind)
			}
			if got := hex.EncodeToString(pw.Key); got != f.keyHex {
				t.Errorf("key=%s want %s", got, f.keyHex)
			}
			if got := hex.EncodeToString(pw.Hash); got != f.hashHex {
				t.Errorf("hash=%s want %s", got, f.hashHex)
			}
			// Verify the real password matches and a wrong one does not.
			if !Verify(pw.Key, pw.Hash, []byte(f.password)) {
				t.Errorf("Verify(correct password %q) = false", f.password)
			}
			if Verify(pw.Key, pw.Hash, []byte(f.password+"x")) {
				t.Errorf("Verify(wrong password) = true")
			}
			// Hash(pw||key) recomputed by Go must equal the Python-hashlib digest.
			if got := hex.EncodeToString(Hash([]byte(f.password), pw.Key)); got != f.hashHex {
				t.Errorf("Hash cross-impl mismatch: %s want %s", got, f.hashHex)
			}
		})
	}
}

func TestParsePlaintextFixture(t *testing.T) {
	// password "LetMeIn2024", stored in the clear (recovered, not cracked).
	pw, err := ParseDPB(mustHex(t, "42405B59576557651BD4F405242303A305E10315"))
	if err != nil {
		t.Fatalf("ParseDPB: %v", err)
	}
	if pw.Kind != KindPlaintext {
		t.Fatalf("Kind=%v, want KindPlaintext", pw.Kind)
	}
	if string(pw.Plaintext) != "LetMeIn2024" {
		t.Errorf("plaintext=%q want %q", pw.Plaintext, "LetMeIn2024")
	}
}

func TestParseNoneFixture(t *testing.T) {
	pw, err := ParseDPB(mustHex(t, "080A282B292B292B"))
	if err != nil {
		t.Fatalf("ParseDPB: %v", err)
	}
	if pw.Kind != KindNone {
		t.Fatalf("Kind=%v, want KindNone", pw.Kind)
	}
}

func TestDataEncryptRoundTrip(t *testing.T) {
	cases := [][]byte{
		{0x00},
		[]byte("LetMeIn2024\x00"),
		bytes.Repeat([]byte{0xAB}, 29),
		{0xFF, 0x00, 0x01, 0x02, 0x7F, 0x80},
	}
	// Exercise all four IgnoredLength values (Seed BAND 6 ∈ {0,2,4,6}).
	for _, seed := range []byte{0x00, 0x02, 0x04, 0x06, 0xA7, 0xFE} {
		for _, data := range cases {
			enc := EncryptData(data, seed, 0x3C, []byte{0xde, 0xad, 0xbe, 0xef})
			got, err := DecryptData(enc)
			if err != nil {
				t.Fatalf("seed=%#x DecryptData: %v", seed, err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("seed=%#x round-trip: got %x want %x", seed, got, data)
			}
		}
	}
}

func TestDecryptDataRejectsGarbage(t *testing.T) {
	// Version byte that is not 2 (Seed XOR VersionEnc != 2) must be rejected.
	if _, err := DecryptData([]byte{0x00, 0x05, 0x00, 0, 0, 0, 0}); err == nil {
		t.Error("expected error for bad version")
	}
	if _, err := DecryptData([]byte{0x00}); err == nil {
		t.Error("expected error for short input")
	}
}
