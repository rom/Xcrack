package pdf

import (
	"bytes"
	"testing"
)

type builder struct {
	name string
	fn   func(user, owner []byte) (*Handler, []byte)
}

var builders = []builder{
	{"rc4-128", NewRC4},
	{"aesv2", NewAESV2},
	{"aesv3-r6", NewAESV3},
}

func TestVerifyAndDecrypt(t *testing.T) {
	user := []byte("userpass")
	owner := []byte("ownerpass")
	for _, b := range builders {
		t.Run(b.name, func(t *testing.T) {
			h, fk := b.fn(user, owner)

			ok, k := h.VerifyUser(user)
			if !ok {
				t.Fatal("VerifyUser(correct) = false")
			}
			if !bytes.Equal(k, fk) {
				t.Fatalf("user file key mismatch")
			}
			if ok, _ := h.VerifyUser([]byte("nope")); ok {
				t.Fatal("VerifyUser(wrong) = true")
			}

			ok, k = h.VerifyOwner(owner)
			if !ok {
				t.Fatal("VerifyOwner(correct) = false")
			}
			if !bytes.Equal(k, fk) {
				t.Fatalf("owner file key mismatch")
			}
			if ok, _ := h.VerifyOwner([]byte("nope")); ok {
				t.Fatal("VerifyOwner(wrong) = true")
			}

			// round-trip object data
			plain := []byte("the secret stream / string contents to analyse")
			enc := h.EncryptData(fk, 7, 0, plain)
			dec, err := h.DecryptData(fk, 7, 0, enc)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(dec, plain) {
				t.Fatalf("object round-trip mismatch:\n got %q\nwant %q", dec, plain)
			}
		})
	}
}

func TestMarshalRoundTrip(t *testing.T) {
	h, _ := NewAESV3([]byte("u"), []byte("o"))
	h2, err := Unmarshal(h.Marshal())
	if err != nil {
		t.Fatal(err)
	}
	if h2.V != h.V || h2.R != h.R || h2.Length != h.Length || h2.P != h.P || h2.Cipher != h.Cipher {
		t.Fatalf("header mismatch: %+v vs %+v", h2, h)
	}
	if !bytes.Equal(h2.U, h.U) || !bytes.Equal(h2.UE, h.UE) || !bytes.Equal(h2.ID, h.ID) {
		t.Fatal("byte fields mismatch")
	}
	ok, _ := h2.VerifyUser([]byte("u"))
	if !ok {
		t.Fatal("reconstructed handler failed to verify")
	}
}
