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

// TestParseRejectsOversizeKeyBits guards the agile KeyBits bound: keyBits/8 sizes
// per-candidate key buffers, so a crafted huge value must be refused at parse.
// A real EncryptAgile blob is the positive control; patching its keyBits to an
// out-of-range value must then be rejected.
func TestParseRejectsOversizeKeyBits(t *testing.T) {
	info, _, err := EncryptAgile([]byte("pw"), []byte("PK\x03\x04payload"), 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseEncryptionInfo(info); err != nil {
		t.Fatalf("positive control: baseline agile info rejected: %v", err)
	}
	bad := bytes.ReplaceAll(info, []byte(`keyBits="256"`), []byte(`keyBits="99999999"`))
	if bytes.Equal(bad, info) {
		t.Fatal("could not patch keyBits in agile info")
	}
	if _, err := ParseEncryptionInfo(bad); err == nil {
		t.Fatal("oversize keyBits accepted")
	}
}
