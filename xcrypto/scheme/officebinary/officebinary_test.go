package officebinary

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // test mirrors the scheme's verifier construction
	"testing"

	"github.com/rom/xcrypto/prim"
)

// Known-answer vectors lifted from the reference implementation
// (nolze/msoffcrypto-tool, MIT) doctests, which pin the exact derived bytes.

var (
	katSalt    = []byte{0xe8, 0x77, 0x2c, 0x1d, 0x91, 0xc5, 0x6a, 0x37, 0x96, 0x47, 0x61, 0xb2, 0x80, 0x18, 0x32, 0x17}
	katOldKey0 = []byte{0x20, 0xbf, 0x32, 0xdd, 0xf5, 0x40, 0x85, 0x8c, 0x51, 0x37, 0x44, 0xaf, 0x0f, 0x24, 0xe0, 0x3c}
	katVerify  = []byte{0xc9, 0xe9, 0x97, 0xd4, 0x54, 0x97, 0x3d, 0x31, 0x0b, 0xb1, 0xba, 0x70, 0x14, 0x26, 0x83, 0x7e}
	katVHash   = []byte{0xb1, 0xde, 0x17, 0x8f, 0x07, 0xe9, 0x89, 0xc4, 0x4d, 0xae, 0x5e, 0x4c, 0xf9, 0x6a, 0xc4, 0x07}
)

func TestRC4KeyKAT(t *testing.T) {
	got := RC4Key([]byte("password1"), katSalt, 0)
	if !bytes.Equal(got, katOldKey0) {
		t.Fatalf("RC4Key mismatch:\n got %x\nwant %x", got, katOldKey0)
	}
}

func TestVerifyRC4KAT(t *testing.T) {
	ok, err := VerifyRC4([]byte("password1"), katSalt, katVerify, katVHash)
	if err != nil || !ok {
		t.Fatalf("VerifyRC4 = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := VerifyRC4([]byte("wrong"), katSalt, katVerify, katVHash); ok {
		t.Fatal("VerifyRC4 accepted a wrong password")
	}
}

func TestVerifyXORKAT(t *testing.T) {
	if !VerifyXOR([]byte("VelvetSweatshop"), 0x9a0a) {
		t.Fatal("VerifyXOR rejected the known VelvetSweatshop verifier")
	}
	if VerifyXOR([]byte("nope"), 0x9a0a) {
		t.Fatal("VerifyXOR accepted a wrong password")
	}
}

func TestTableSizes(t *testing.T) {
	if len(xorMatrix) != 105 || len(xorInitialCode) != 15 || len(xorPadArray) != 15 {
		t.Fatalf("XOR table sizes: matrix=%d initial=%d pad=%d", len(xorMatrix), len(xorInitialCode), len(xorPadArray))
	}
}

func TestVerifyCryptoAPIRoundTrip(t *testing.T) {
	// Construct a verifier the way the scheme does, then confirm it verifies.
	pw := []byte("Password1234_")
	salt := bytes.Repeat([]byte{0xA5}, 16)
	keyBits := 128
	verifier := bytes.Repeat([]byte{0x42}, 16)
	h := sha1.Sum(verifier) //nolint:gosec
	plain := append(append([]byte{}, verifier...), h[:]...)
	key := CryptoAPIKey(pw, salt, keyBits, 0)
	enc, err := prim.RC4(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	ok, err := VerifyCryptoAPI(pw, salt, keyBits, enc[:16], enc[16:36])
	if err != nil || !ok {
		t.Fatalf("VerifyCryptoAPI = %v, %v; want true", ok, err)
	}
	if ok, _ := VerifyCryptoAPI([]byte("other"), salt, keyBits, enc[:16], enc[16:36]); ok {
		t.Fatal("VerifyCryptoAPI accepted a wrong password")
	}
}

func TestCryptoAPI40BitKeyPadding(t *testing.T) {
	key := CryptoAPIKey([]byte("x"), bytes.Repeat([]byte{1}, 16), 40, 0)
	if len(key) != 16 {
		t.Fatalf("40-bit key length = %d; want 16 (zero-padded)", len(key))
	}
	for _, b := range key[5:] {
		if b != 0 {
			t.Fatalf("40-bit key not zero-padded past 5 bytes: %x", key)
		}
	}
}

func TestDecryptSymmetryMultiBlock(t *testing.T) {
	pw := []byte("hunter2")
	salt := bytes.Repeat([]byte{0x11}, 16)
	plain := bytes.Repeat([]byte("the quick brown fox "), 200) // > one 512/1024 block

	for _, bs := range []int{0x200, 0x400} {
		enc, err := DecryptCryptoAPI(pw, salt, 128, plain, bs, 0)
		if err != nil {
			t.Fatal(err)
		}
		dec, err := DecryptCryptoAPI(pw, salt, 128, enc, bs, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(dec, plain) {
			t.Fatalf("CryptoAPI not symmetric at blocksize %d", bs)
		}
	}

	enc, _ := DecryptRC4(pw, salt, plain, 0x200)
	dec, _ := DecryptRC4(pw, salt, enc, 0x200)
	if !bytes.Equal(dec, plain) {
		t.Fatal("RC4 (97/2000) not symmetric across blocks")
	}
}

func TestXORMethod1RoundTrip(t *testing.T) {
	pw := []byte("123456789012345")
	// A mixed layout: literal header bytes (>=0), then encrypted runs (-1), and
	// a -2 run (Excel's lbPlyPos-adjacent data), repeated to cross the 16-byte
	// key-array boundary several times.
	plain := []int{0x09, 0x08, 0x10, 0x00} // a literal "header"
	plaintext := []byte{0x09, 0x08, 0x10, 0x00}
	for i := 0; i < 200; i++ {
		marker := -1
		if i%7 == 0 {
			marker = -2
		}
		plain = append(plain, marker)
		plaintext = append(plaintext, byte(i*131+17))
	}
	cipher, ok := EncryptXORMethod1(pw, plaintext, plain)
	if !ok {
		t.Fatal("EncryptXORMethod1 failed")
	}
	got, ok := DecryptXORMethod1(pw, cipher, plain)
	if !ok {
		t.Fatal("DecryptXORMethod1 failed")
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("XOR method-1 round trip mismatch:\n got %x\nwant %x", got, plaintext)
	}
}

func TestXORArrayDerivable(t *testing.T) {
	if _, ok := XORKeyArray([]byte("123456789012345")); !ok {
		t.Fatal("XORKeyArray failed for a 15-char password")
	}
	if _, ok := XORKeyArray(nil); ok {
		t.Fatal("XORKeyArray accepted an empty password")
	}
	if _, ok := XORKeyArray(bytes.Repeat([]byte("x"), 16)); ok {
		t.Fatal("XORKeyArray accepted a 16-char password (max is 15)")
	}
}
