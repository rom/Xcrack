package odf

import (
	"bytes"
	"io"
	"testing"

	"github.com/rom/xfileformats"
)

func TestODFFormatRoundTrip(t *testing.T) {
	password := []byte("libre-secret")
	content := bytes.Repeat([]byte("<text:p>confidential paragraph</text:p>"), 60)
	data, err := BuildEncryptedODF(password, content, 1000)
	if err != nil {
		t.Fatal(err)
	}

	f := New()
	peek := data
	if len(peek) > 512 {
		peek = peek[:512]
	}
	if conf, ok := f.Detect(peek); !ok || conf < 0.9 {
		t.Fatalf("Detect ODF: ok=%v conf=%v", ok, conf)
	}
	entries, err := f.Entries(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var ce *xfileformats.Entry
	for _, e := range entries {
		if e.Path == "content.xml" {
			ce = e
		}
	}
	if ce == nil || !ce.Encrypted {
		t.Fatalf("content.xml encrypted entry not found")
	}
	if ok, err := ce.Verify(password); err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	if ok, _ := ce.Verify([]byte("wrong")); ok {
		t.Fatal("Verify(wrong) = true")
	}
	r, err := ce.Open(password)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(r); !bytes.Equal(got, content) {
		t.Fatalf("decrypted content mismatch")
	}
}

func TestODFFuzzSeed(t *testing.T) {
	// non-ODF zip should not be detected as ODF
	if _, ok := New().Detect([]byte("PK\x03\x04 ordinary zip")); ok {
		t.Error("ordinary zip must not detect as ODF")
	}
}
