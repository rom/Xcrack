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

func TestParseRejectsNonKDBX(t *testing.T) {
	if _, err := Parse([]byte("not a kdbx file at all")); err == nil {
		t.Fatal("expected error for non-KDBX input")
	}
	// Right magic, wrong (KDBX3) major version → unsupported.
	hdr := []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5, 0x01, 0x00, 0x03, 0x00}
	if _, err := Parse(hdr); err == nil {
		t.Fatal("expected KDBX3 to be reported unsupported")
	}
}
