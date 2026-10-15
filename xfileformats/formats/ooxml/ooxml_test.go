package ooxml

import (
	stdzip "archive/zip"
	"bytes"
	"io"
	"testing"

	"github.com/rom/xfileformats"
)

// makeInnerZip builds a small plaintext ZIP to stand in for the OOXML package.
func makeInnerZip(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(content)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestOOXMLAgileFormatRoundTrip(t *testing.T) {
	password := []byte("Office365!")
	pkg := makeInnerZip(t, "word/document.xml", []byte("<document>hello</document>"))
	data, err := BuildEncryptedAgile(password, pkg, 100)
	if err != nil {
		t.Fatal(err)
	}

	f := New()
	if _, ok := f.Detect(data[:8]); !ok {
		t.Fatal("Detect should recognize the compound file")
	}
	if !f.Caps().Encrypted {
		t.Fatal("OOXML should advertise Encrypted")
	}

	ra := bytes.NewReader(data)
	ch, err := f.Probe(ra, int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ch.Scheme != "ooxml-agile" {
		t.Fatalf("scheme = %q", ch.Scheme)
	}

	ok, key, err := f.Verify(ch, password)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) ok=%v err=%v", ok, err)
	}
	if bad, _, _ := f.Verify(ch, []byte("wrong")); bad {
		t.Fatal("Verify(wrong) = true")
	}

	r, err := f.Decrypt(ra, int64(len(data)), ch, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, pkg) {
		t.Fatalf("decrypted package mismatch: got %d bytes want %d", len(got), len(pkg))
	}
}

func TestProbeRejectsNonEncryptedCFB(t *testing.T) {
	// A compound file without an EncryptionInfo stream is not an encrypted doc.
	ra := bytes.NewReader(make([]byte, 4096))
	if _, err := New().Probe(ra, 4096); err == nil {
		t.Fatal("expected Probe to reject a non-CFB / non-encrypted input")
	}
	_ = xfileformats.ErrUnsupported
}
