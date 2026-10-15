package xcrack

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/rom/xcrypto/candidates"
	xpdf "github.com/rom/xcrypto/scheme/pdf"
	"github.com/rom/xfileformats/formats/pdf"
)

func TestEncryptedPDFDecrypt(t *testing.T) {
	user := "letmein"
	doc, wantStream, wantString := pdf.BuildEncryptedPDF([]byte(user), []byte("owner"), xpdf.CipherAESV2)

	src := candidates.Explicit("no", user)
	res, err := Process(context.Background(), bytes.NewReader(doc), int64(len(doc)), src, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	root := res.Root
	if root.Format != "pdf" || !root.WasEncrypted || root.Password != user || root.Status != StatusDecrypted {
		t.Fatalf("root: fmt=%q enc=%v pw=%q status=%v", root.Format, root.WasEncrypted, root.Password, root.Status)
	}
	if root.Content == nil {
		t.Fatal("decrypted PDF should be a leaf with content")
	}
	rc, _ := root.Content.Open()
	out, _ := readAllRC(rc)
	if bytes.Contains(out, []byte("/Encrypt")) {
		t.Error("output still references /Encrypt")
	}
	if !bytes.Contains(out, wantStream) {
		t.Error("decrypted content stream missing from output")
	}
	if !bytes.Contains(out, []byte(hex.EncodeToString(wantString))) {
		t.Error("decrypted string missing from output")
	}
}

func TestPlainPDFPassesThrough(t *testing.T) {
	plain := []byte("%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF")
	res, err := Process(context.Background(), bytes.NewReader(plain), int64(len(plain)), candidates.Explicit("x"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	// A non-encrypted PDF must be handed back as a plain leaf, not an error.
	if res.Root.Status != StatusPlain || res.Root.Content == nil {
		t.Fatalf("plain PDF: status=%v content=%v", res.Root.Status, res.Root.Content != nil)
	}
	rc, _ := res.Root.Content.Open()
	out, _ := readAllRC(rc)
	if !bytes.Equal(out, plain) {
		t.Error("plain PDF content should pass through unchanged")
	}
}
