package pdf

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
)

// keyIndex maps a 5-byte little-endian file key to its sweep index.
func keyIndex(key []byte) uint64 {
	var b [8]byte
	copy(b[:5], key)
	return binary.LittleEndian.Uint64(b[:])
}

// TestRC4KeyAttackR2 builds a V1/R2 40-bit handler for a known password and
// confirms the direct key sweep recovers the real file key from a small window
// around it (we cannot sweep the whole 2^40 in a unit test), that the recovered
// key decrypts an object, and that the handler is reported attackable.
func TestRC4KeyAttackR2(t *testing.T) {
	user := []byte("a long random user password nobody would ever guess 9f3b")
	h, fk := NewRC4R2(user, []byte("ownerpw"))

	if !h.RC4KeyAttackable() {
		t.Fatal("RC4KeyAttackable() = false for a 40-bit R2 handler")
	}
	if len(fk) != 5 {
		t.Fatalf("file key is %d bytes, want 5", len(fk))
	}
	// Sanity: the scheme itself accepts the password and yields this key.
	if ok, k := h.VerifyUser(user); !ok || !bytes.Equal(k, fk) {
		t.Fatalf("VerifyUser sanity failed: ok=%v", ok)
	}

	idx := keyIndex(fk)
	const window = 4096
	start := uint64(0)
	if idx > window {
		start = idx - window
	}
	got, found, err := h.RC4KeyAttack(context.Background(), start, 2*window+1)
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("RC4KeyAttack did not find the key in the window")
	}
	if !bytes.Equal(got, fk) {
		t.Fatalf("recovered key %x, want %x", got, fk)
	}

	// The recovered key must decrypt an object with no password involved.
	plain := []byte("object payload recovered via the 40-bit key attack")
	enc := h.EncryptData(fk, 4, 0, plain)
	dec, err := h.DecryptData(got, 4, 0, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatalf("decrypt with recovered key: got %q want %q", dec, plain)
	}

	// A wrong key must not verify.
	wrong := append([]byte(nil), fk...)
	wrong[0]++
	if h.VerifyFileKey(wrong) {
		t.Fatal("VerifyFileKey accepted a wrong key")
	}
}

// TestRC4KeyAttackParallelR2 exercises the parallel driver over a small window.
func TestRC4KeyAttackParallelR2(t *testing.T) {
	user := []byte("another unguessable passphrase 7c21")
	h, fk := NewRC4R2(user, nil)
	idx := keyIndex(fk)
	const window = 8192
	start := uint64(0)
	if idx > window {
		start = idx - window
	}
	got, found, err := h.RC4KeyAttackParallel(context.Background(), start, 2*window+1, 4)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !bytes.Equal(got, fk) {
		t.Fatalf("parallel sweep: found=%v got=%x want=%x", found, got, fk)
	}
}

// TestRC4KeyAttackR3 covers the general (computeU) path: an R3 handler forced to
// a 40-bit key is attackable the same way, just via the longer verifier.
func TestRC4KeyAttackR3_40bit(t *testing.T) {
	h := &Handler{
		V: 2, R: 3, Length: 5, P: -3904,
		ID: []byte("0123456789abcdef"), EncryptMetadata: true, Cipher: CipherRC4,
	}
	user := []byte("r3 40-bit passphrase, also long and random e5a0")
	h.O = h.computeO([]byte("ownerpw"), user)
	fk := h.fileKeyFromUser(user)
	u := h.computeU(fk)
	h.U = make([]byte, 32)
	copy(h.U, u)

	if !h.RC4KeyAttackable() {
		t.Fatal("RC4KeyAttackable() = false for a 40-bit R3 handler")
	}
	idx := keyIndex(fk)
	const window = 2048
	start := uint64(0)
	if idx > window {
		start = idx - window
	}
	got, found, err := h.RC4KeyAttack(context.Background(), start, 2*window+1)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !bytes.Equal(got, fk) {
		t.Fatalf("R3 sweep: found=%v got=%x want=%x", found, got, fk)
	}
}

// TestRC4KeyAttackNotAttackable confirms the stronger schemes are rejected
// rather than swept futilely.
func TestRC4KeyAttackNotAttackable(t *testing.T) {
	for _, b := range []builder{{"rc4-128", NewRC4}, {"aesv2", NewAESV2}, {"aesv3-r6", NewAESV3}} {
		h, _ := b.fn([]byte("u"), []byte("o"))
		if h.RC4KeyAttackable() {
			t.Fatalf("%s reported RC4KeyAttackable()=true", b.name)
		}
		if _, found, _ := h.RC4KeyAttack(context.Background(), 0, 1<<20); found {
			t.Fatalf("%s key attack returned a spurious hit", b.name)
		}
	}
}

// TestRC4KeyAttackQPDFVector is the external-oracle KAT: /O, /U and /ID below
// were taken from a real 40-bit (V1/R2) PDF produced by qpdf
//
//	qpdf --allow-weak-crypto --encrypt userpw ownerpw 40 --print=n --modify=n \
//	     -- in.pdf out.pdf
//
// so the scheme's verifier and the key sweep are validated against an
// independent producer, not just against our own encryptor. We first confirm
// the scheme accepts "userpw" (proving the construction matches qpdf), then
// confirm the sweep recovers that same file key from a window around it.
func TestRC4KeyAttackQPDFVector(t *testing.T) {
	h := &Handler{
		V: 1, R: 2, Length: 5, P: -16, EncryptMetadata: true, Cipher: CipherRC4,
		O: []byte{
			0xfd, 0x7d, 0x1b, 0xc1, 0x57, 0xfc, 0xf7, 0x6e, 0x07, 0x9d, 0x3d, 0xaf, 0x15, 0x98, 0x1c, 0xc0,
			0x36, 0x86, 0x81, 0x9d, 0x8f, 0xfd, 0x9e, 0xa5, 0x83, 0x6d, 0x4f, 0xec, 0x05, 0xb4, 0xf0, 0xaa,
		},
		U: []byte{
			0x5b, 0xf1, 0xc3, 0xc9, 0x81, 0x3d, 0x51, 0x1e, 0x22, 0x65, 0xdb, 0xb4, 0x1a, 0xc2, 0x3d, 0xcd,
			0x28, 0x68, 0xee, 0x29, 0x8e, 0x5b, 0x16, 0x3a, 0x36, 0x5f, 0x2a, 0x8a, 0xb2, 0xcf, 0x68, 0xfc,
		},
		ID: []byte{
			0x63, 0x9e, 0x16, 0x7a, 0x00, 0xad, 0x0e, 0xd5, 0x90, 0x23, 0x31, 0x11, 0x12, 0x8c, 0x93, 0xdc,
		},
	}

	ok, fk := h.VerifyUser([]byte("userpw"))
	if !ok {
		t.Fatal("scheme rejected the qpdf user password — construction disagrees with qpdf")
	}
	if ok, _ := h.VerifyOwner([]byte("ownerpw")); !ok {
		t.Fatal("scheme rejected the qpdf owner password")
	}
	if !h.RC4KeyAttackable() {
		t.Fatal("qpdf 40-bit vector not reported attackable")
	}

	idx := keyIndex(fk)
	const window = 4096
	start := uint64(0)
	if idx > window {
		start = idx - window
	}
	got, found, err := h.RC4KeyAttack(context.Background(), start, 2*window+1)
	if err != nil {
		t.Fatal(err)
	}
	if !found || !bytes.Equal(got, fk) {
		t.Fatalf("qpdf vector sweep: found=%v got=%x want=%x", found, got, fk)
	}
}
