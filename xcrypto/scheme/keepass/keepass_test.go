package keepass

import (
	"os"
	"testing"
)

// TestVerifyRealKDBX4 cross-validates the header-HMAC verifier against KDBX4
// databases produced by pykeepass (an independent implementation); passphrase
// "opensesame". See testdata/ATTRIBUTION.md.
func TestVerifyRealKDBX4(t *testing.T) {
	cases := []struct {
		file       string
		wantMemKiB uint64
		short      bool // skip under -short (heavy KDF)
	}{
		{"testdata/pykeepass-argon2d.kdbx", 1024, false},
		{"testdata/pykeepass-argon2d-default.kdbx", 65536, true},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			if c.short && testing.Short() {
				t.Skip("heavy KDF; skipped under -short")
			}
			data, err := os.ReadFile(c.file)
			if err != nil {
				t.Skip("fixture missing")
			}
			k, err := Parse(data)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if k.Major != 4 {
				t.Fatalf("major = %d, want 4", k.Major)
			}
			if k.kdf.uuid != uuidArgon2d {
				t.Fatalf("kdf uuid = %x, want argon2d", k.kdf.uuid)
			}
			if k.kdf.memoryKiB != c.wantMemKiB {
				t.Errorf("memoryKiB = %d, want %d", k.kdf.memoryKiB, c.wantMemKiB)
			}
			if ok, err := k.Verify([]byte("opensesame")); err != nil || !ok {
				t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
			}
			if ok, _ := k.Verify([]byte("wrong")); ok {
				t.Fatal("Verify(wrong) = true")
			}
			if ch := k.Challenge(); ch.Scheme != "keepass-kdbx4-argon2d" {
				t.Errorf("scheme = %q", ch.Scheme)
			}
		})
	}
}

// TestVerifyRealKDBX3 cross-validates the stream-start-bytes verifier against a
// legacy KDBX3.1 (AES-KDF) database, itself validated by KeePassXC and
// pykeepass; passphrase "opensesame". See testdata/ATTRIBUTION.md.
func TestVerifyRealKDBX3(t *testing.T) {
	data, err := os.ReadFile("testdata/kdbx3-aeskdf.kdbx")
	if err != nil {
		t.Skip("fixture missing")
	}
	k, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if k.Major != 3 {
		t.Fatalf("major = %d, want 3", k.Major)
	}
	if k.transformRnds != 6000 {
		t.Errorf("transformRounds = %d, want 6000", k.transformRnds)
	}
	if ok, err := k.Verify([]byte("opensesame")); err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	for _, bad := range []string{"OpenSesame", "opensesam", "", "wrong"} {
		if ok, _ := k.Verify([]byte(bad)); ok {
			t.Fatalf("Verify(%q) = true", bad)
		}
	}
	if ch := k.Challenge(); ch.Scheme != "keepass-kdbx3-aeskdf" {
		t.Errorf("scheme = %q", ch.Scheme)
	}
	// Re-parsing the minimal serialized prefix must verify identically.
	k2, err := Parse(k.Serialized())
	if err != nil {
		t.Fatalf("Parse(Serialized): %v", err)
	}
	if ok, err := k2.Verify([]byte("opensesame")); err != nil || !ok {
		t.Fatalf("Verify after round-trip: ok=%v err=%v", ok, err)
	}
}

func TestParseRejectsNonKDBX(t *testing.T) {
	if _, err := Parse([]byte("not a kdbx file at all")); err == nil {
		t.Fatal("expected error for non-KDBX input")
	}
	// Right magic, KDBX3 major but a truncated header (no fields) → malformed.
	hdr := []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x01, 0x00, 0x03, 0x00}
	if _, err := Parse(hdr); err == nil {
		t.Fatal("expected truncated KDBX3 header to be rejected")
	}
	// Right magic, unknown major version → unsupported.
	hdr2 := []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x01, 0x00, 0x05, 0x00}
	if _, err := Parse(hdr2); err == nil {
		t.Fatal("expected unknown major version to be rejected")
	}
}
