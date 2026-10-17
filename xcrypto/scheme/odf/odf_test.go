package odf

import (
	"bytes"
	"compress/flate"
	"io"
	"testing"
)

func TestODFRoundTrip(t *testing.T) {
	password := []byte("odf-secret")
	content := bytes.Repeat([]byte("<office:body>confidential</office:body>"), 80)
	raw, p, err := EncryptEntry(password, content, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := Verify(password, p, raw); err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	if ok, _ := Verify([]byte("wrong"), p, raw); ok {
		t.Fatal("Verify(wrong) = true")
	}
	comp, err := DecryptCompressed(password, p, raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(flate.NewReader(bytes.NewReader(comp)))
	if err != nil && err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
	if int64(len(got)) < p.UncompressedSize {
		t.Fatalf("inflated %d bytes, want >= %d", len(got), p.UncompressedSize)
	}
	got = got[:p.UncompressedSize]
	if !bytes.Equal(got, content) {
		t.Fatal("ODF content mismatch")
	}
}

func TestODFRoundTripGCM(t *testing.T) {
	password := []byte("odf-secret")
	content := bytes.Repeat([]byte("<office:body>gcm confidential</office:body>"), 80)
	raw, p, err := EncryptEntryGCM(password, content, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if sc := Challenge(p).Scheme; sc != "odf-aes256-gcm" {
		t.Fatalf("scheme = %q, want odf-aes256-gcm", sc)
	}
	if ok, err := Verify(password, p, raw); err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	if ok, err := Verify([]byte("wrong"), p, raw); err != nil || ok {
		t.Fatalf("Verify(wrong): ok=%v err=%v (want false,nil)", ok, err)
	}
	// A single flipped ciphertext byte must fail the GCM tag.
	tampered := append([]byte(nil), raw...)
	tampered[0] ^= 0x01
	if ok, _ := Verify(password, p, tampered); ok {
		t.Fatal("Verify of tampered ciphertext = true (GCM tag should reject)")
	}
	comp, err := DecryptCompressed(password, p, raw)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(flate.NewReader(bytes.NewReader(comp)))
	if err != nil && err != io.ErrUnexpectedEOF {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("ODF GCM content mismatch")
	}
}

// TestODFVerifyWithKey proves the GPU-offload path matches the CPU verifier:
// VerifyWithKey, given the key DeriveKey would produce (what the accelerator
// derives via PBKDF2 over the start-key hash), returns the same verdict as
// Verify, for both CBC and GCM, and rejects a wrong key.
func TestODFVerifyWithKey(t *testing.T) {
	for _, tc := range []struct {
		name string
		enc  func([]byte, []byte, int) ([]byte, EntryParams, error)
	}{
		{"cbc", EncryptEntry},
		{"gcm", EncryptEntryGCM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password := []byte("odf-secret")
			content := bytes.Repeat([]byte("<office:body>accel</office:body>"), 80)
			raw, p, err := tc.enc(password, content, 1000)
			if err != nil {
				t.Fatal(err)
			}
			preHash, keyLen, ok := AccelStartHash(p)
			if !ok {
				t.Fatal("AccelStartHash reported not accelerable")
			}
			if preHash != "sha256" || keyLen != 32 {
				t.Fatalf("AccelStartHash = (%q,%d), want (sha256,32)", preHash, keyLen)
			}
			key, err := DeriveKey(password, p)
			if err != nil {
				t.Fatal(err)
			}
			if ok, err := VerifyWithKey(key, p, raw); err != nil || !ok {
				t.Fatalf("VerifyWithKey(correct): ok=%v err=%v", ok, err)
			}
			wrong := make([]byte, len(key))
			copy(wrong, key)
			wrong[0] ^= 0xff
			if ok, _ := VerifyWithKey(wrong, p, raw); ok {
				t.Fatal("VerifyWithKey(wrong key) = true")
			}
		})
	}
}

func TestODFBlowfishUnsupported(t *testing.T) {
	p := EntryParams{Algorithm: "Blowfish CFB", IV: make([]byte, 8), Salt: make([]byte, 16), Iterations: 1024, KeySize: 16, StartKeyHash: "SHA1"}
	if _, err := DecryptCompressed([]byte("x"), p, make([]byte, 32)); err == nil {
		t.Fatal("expected Blowfish to be reported unsupported")
	}
}
