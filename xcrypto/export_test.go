package xcrypto

import (
	"bytes"
	"reflect"
	"testing"
)

func TestChallengeExportRoundTrip(t *testing.T) {
	orig := &Challenge{
		Scheme: "mso-rc4-cryptoapi",
		KDF:    KDFSpec{Algo: "office-rc4-cryptoapi-sha1", Iterations: 50000, Salt: []byte{1, 2, 3, 4, 0xFF}, KeyLen: 16},
		Cipher: CipherSpec{Algo: "rc4", KeyBits: 128},
		Verifier: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
			0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x10, 0x20, 0x30, 0x40},
		Extra:             map[string][]byte{"enc_verifier": {0xDE, 0xAD, 0xBE, 0xEF}, "spin": {0x00, 0x10}},
		DecryptedSizeHint: 4096,
	}

	data, err := MarshalChallenge(orig, "invoice.doc!/WordDocument")
	if err != nil {
		t.Fatal(err)
	}
	got, source, err := UnmarshalChallenge(data)
	if err != nil {
		t.Fatal(err)
	}
	if source != "invoice.doc!/WordDocument" {
		t.Errorf("source = %q", source)
	}
	if got.Scheme != orig.Scheme || got.Cipher != orig.Cipher || got.KDF.Algo != orig.KDF.Algo ||
		got.KDF.Iterations != orig.KDF.Iterations || got.KDF.KeyLen != orig.KDF.KeyLen ||
		got.DecryptedSizeHint != orig.DecryptedSizeHint {
		t.Fatalf("scalar fields differ:\n got %+v\nwant %+v", got, orig)
	}
	if !bytes.Equal(got.KDF.Salt, orig.KDF.Salt) || !bytes.Equal(got.Verifier, orig.Verifier) {
		t.Fatal("salt/verifier bytes differ after round trip")
	}
	if !reflect.DeepEqual(got.Extra, orig.Extra) {
		t.Fatalf("extra differs:\n got %v\nwant %v", got.Extra, orig.Extra)
	}
}

func TestUnmarshalChallengeRejectsBadVersion(t *testing.T) {
	if _, _, err := UnmarshalChallenge([]byte(`{"xcrack_challenge_version":999,"scheme":"x"}`)); err == nil {
		t.Fatal("expected an error for an unsupported version")
	}
	if _, _, err := UnmarshalChallenge([]byte(`{"xcrack_challenge_version":1,"verifier_hex":"zz"}`)); err == nil {
		t.Fatal("expected an error for malformed hex")
	}
}

func TestRecoveredPasswordRoundTrip(t *testing.T) {
	data, err := MarshalRecoveredPassword("invoice.doc", "Password1234_")
	if err != nil {
		t.Fatal(err)
	}
	r, err := UnmarshalRecoveredPassword(data)
	if err != nil {
		t.Fatal(err)
	}
	if r.Password != "Password1234_" || r.Source != "invoice.doc" {
		t.Fatalf("round trip mismatch: %+v", r)
	}
}
