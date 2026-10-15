package zipcrypto

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	pw := []byte("infected")
	payload := []byte("this stands in for the compressed payload bytes")
	const check = 0x42
	raw := EncryptRaw(pw, make([]byte, HeaderLen-1), check, payload)

	if !HeaderOK(pw, raw, check) {
		t.Fatal("HeaderOK(correct) = false")
	}
	if HeaderOK([]byte("wrong-pass-xyz"), raw, check) {
		t.Fatal("HeaderOK(wrong) = true (expected the 1/256 check to usually reject)")
	}
	got, err := Decrypt(pw, raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Decrypt mismatch:\n got %q\nwant %q", got, payload)
	}
}

func TestShortInput(t *testing.T) {
	if _, err := Decrypt([]byte("p"), []byte{1, 2, 3}); err == nil {
		t.Fatal("expected error on sub-header input")
	}
}
