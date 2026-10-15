package ooxml

import (
	"bytes"
	"testing"
)

func TestAgileRoundTrip(t *testing.T) {
	password := []byte("S3cr3t-Pass!")
	pkg := bytes.Repeat([]byte("PK\x03\x04 inner office zip bytes "), 300) // ~ multi-segment
	info, enc, err := EncryptAgile(password, pkg, 120)
	if err != nil {
		t.Fatal(err)
	}
	i, err := ParseEncryptionInfo(info)
	if err != nil {
		t.Fatal(err)
	}
	if i.Scheme() != "ooxml-agile" {
		t.Fatalf("scheme = %s", i.Scheme())
	}
	if ok, err := i.Verify(password); err != nil || !ok {
		t.Fatalf("Verify(correct) ok=%v err=%v", ok, err)
	}
	if ok, _ := i.Verify([]byte("wrong")); ok {
		t.Fatal("Verify(wrong) = true")
	}
	got, err := i.DecryptPackage(password, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pkg) {
		t.Fatalf("decrypt mismatch: got %d bytes, want %d", len(got), len(pkg))
	}
}

func TestStandardRoundTrip(t *testing.T) {
	for _, keyLen := range []int{16, 32} { // AES-128, AES-256
		password := []byte("Office2007pw")
		pkg := []byte("PK\x03\x04 the inner document package content")
		info, enc, err := EncryptStandard(password, pkg, keyLen)
		if err != nil {
			t.Fatal(err)
		}
		i, err := ParseEncryptionInfo(info)
		if err != nil {
			t.Fatal(err)
		}
		if i.Scheme() != "ooxml-standard" {
			t.Fatalf("scheme = %s", i.Scheme())
		}
		if ok, err := i.Verify(password); err != nil || !ok {
			t.Fatalf("keyLen=%d Verify(correct) ok=%v err=%v", keyLen, ok, err)
		}
		if ok, _ := i.Verify([]byte("nope")); ok {
			t.Fatalf("keyLen=%d Verify(wrong) = true", keyLen)
		}
		got, err := i.DecryptPackage(password, enc)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, pkg) {
			t.Fatalf("keyLen=%d decrypt mismatch", keyLen)
		}
	}
}
