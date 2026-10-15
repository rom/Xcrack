package pdf

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	xpdf "github.com/rom/xcrypto/scheme/pdf"
)

func TestPDFFormatRoundTrip(t *testing.T) {
	user, owner := []byte("userpw"), []byte("ownerpw")
	for _, c := range []struct {
		name   string
		cipher xpdf.Cipher
	}{
		{"rc4", xpdf.CipherRC4},
		{"aesv2", xpdf.CipherAESV2},
		{"aesv3", xpdf.CipherAESV3},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc, wantStream, wantString := BuildEncryptedPDF(user, owner, c.cipher)
			f := New()
			if _, ok := f.Detect(doc[:16]); !ok {
				t.Fatal("Detect failed")
			}
			ra := bytes.NewReader(doc)
			ch, err := f.Probe(ra, int64(len(doc)))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}

			// user + owner verify, correct and wrong
			ok, key, _ := f.Verify(ch, user)
			if !ok {
				t.Fatal("Verify(user) failed")
			}
			if ok, _, _ := f.Verify(ch, []byte("wrong")); ok {
				t.Fatal("Verify(wrong) = true")
			}
			if ok, _, _ := f.Verify(ch, owner); !ok {
				t.Fatal("Verify(owner) failed")
			}

			r, err := f.Decrypt(ra, int64(len(doc)), ch, key)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}
			out, _ := io.ReadAll(r)
			if bytes.Contains(out, []byte("/Encrypt")) {
				t.Error("decrypted PDF still references /Encrypt")
			}
			if !bytes.Contains(out, wantStream) {
				t.Errorf("decrypted stream not found in output")
			}
			// Decrypted strings are re-emitted as hex strings (valid PDF).
			if !bytes.Contains(out, []byte(hex.EncodeToString(wantString))) {
				t.Errorf("decrypted author string not found in output (as hex)")
			}
		})
	}
}

func TestProbeNotEncrypted(t *testing.T) {
	plain := []byte("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF")
	_, err := New().Probe(bytes.NewReader(plain), int64(len(plain)))
	if err == nil {
		t.Fatal("expected an error for a non-encrypted PDF")
	}
	// It must be ErrNotEncrypted so the engine treats it as a plain leaf.
	if err.Error() != "xfileformats: not encrypted" {
		t.Fatalf("got %v, want ErrNotEncrypted", err)
	}
}
