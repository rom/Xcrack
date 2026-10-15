package pdf

import (
	"bytes"
	"testing"

	xpdf "github.com/rom/xcrypto/scheme/pdf"
)

func FuzzProbe(f *testing.F) {
	doc, _, _ := BuildEncryptedPDF([]byte("u"), []byte("o"), xpdf.CipherAESV2)
	f.Add(doc)
	f.Add([]byte("%PDF-1.4\ntrailer<< /Root 1 0 R >>"))
	f.Add([]byte("%PDF-1.7 /Encrypt 6 0 R"))
	f.Add([]byte{})

	fmt := New()
	f.Fuzz(func(t *testing.T, b []byte) {
		ch, err := fmt.Probe(bytes.NewReader(b), int64(len(b)))
		if err != nil || ch == nil {
			return
		}
		fmt.Verify(ch, []byte("u"))
	})
}

// FuzzRebuild fuzzes the object scanner / decrypt-rebuild pass on arbitrary
// bytes with a fixed handler and key.
func FuzzRebuild(f *testing.F) {
	h, key := xpdf.NewAESV2([]byte("u"), []byte("o"))
	doc, _, _ := BuildEncryptedPDF([]byte("u"), []byte("o"), xpdf.CipherAESV2)
	f.Add(doc)
	f.Add([]byte("1 0 obj << /Length 5 >> stream\nhello\nendstream endobj"))
	f.Add([]byte("garbage 9 9 obj (x) endobj"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		rebuild(b, h, key)
	})
}
