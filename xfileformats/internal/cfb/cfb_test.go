package cfb

import (
	"bytes"
	"testing"
)

func TestBuildOpenRoundTrip(t *testing.T) {
	small := []byte("EncryptionInfo: a small stream that lives in the mini-FAT")
	large := bytes.Repeat([]byte("EncryptedPackage segment "), 400) // > 4096 => regular FAT
	data := Build([]StreamEntry{
		{Name: "EncryptionInfo", Data: small},
		{Name: "EncryptedPackage", Data: large},
	})
	if !IsCFB(data) {
		t.Fatal("Build output is not recognized as CFB")
	}
	f, err := Open(data)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	gotSmall, ok := f.Stream("EncryptionInfo")
	if !ok || !bytes.Equal(gotSmall, small) {
		t.Fatalf("EncryptionInfo mismatch: ok=%v len=%d want=%d", ok, len(gotSmall), len(small))
	}
	gotLarge, ok := f.Stream("EncryptedPackage")
	if !ok || !bytes.Equal(gotLarge, large) {
		t.Fatalf("EncryptedPackage mismatch: ok=%v len=%d want=%d", ok, len(gotLarge), len(large))
	}
}

func TestOpenRejectsGarbage(t *testing.T) {
	if _, err := Open([]byte("not a compound file at all, really")); err == nil {
		t.Fatal("expected error for non-CFB input")
	}
	if _, err := Open(make([]byte, 600)); err == nil {
		t.Fatal("expected error for zero header")
	}
}
