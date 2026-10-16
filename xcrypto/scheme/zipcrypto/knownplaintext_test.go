package zipcrypto

import (
	"bytes"
	"testing"
)

// key2SeqOf returns the key2 (C) sequence that a password-derived cipher produces
// over the first len(plain) encrypted bytes. It stands in for the front-half
// "Zreduction" reducer (not yet shipped) so the verified back half can be tested
// end to end.
func key2SeqOf(password string, plain []byte) []uint32 {
	k := NewKeys([]byte(password))
	seq := make([]uint32, len(plain))
	for i := range plain {
		seq[i] = k.k2
		k.update(plain[i])
	}
	return seq
}

// TestTablesAreExactInverses verifies the attack's lookup tables are exact
// inverses of the forward cipher primitives (a wrong table silently breaks the
// whole attack).
func TestTablesAreExactInverses(t *testing.T) {
	m, mi := uint32(multConst), uint32(multInvConst)
	if got := m * mi; got != 1 {
		t.Fatalf("MULTINV wrong: mult*inv = 0x%08x", got)
	}
	// crc32inv inverts crc32update for a long pseudo-random walk of states/bytes.
	st := uint32(0x9e3779b9)
	for i := 0; i < 1<<20; i++ {
		b := byte(st >> 13)
		if crc32inv(crc32update(st, b), b) != st {
			t.Fatalf("crc32inv failed at state 0x%08x byte %02x", st, b)
		}
		st = st*1664525 + 1013904223
	}
	// Every keystream byte's low-16 table entry reproduces that byte.
	for ks := 0; ks < 256; ks++ {
		for _, low := range ksLow16[ks] {
			if keystreamOf(uint32(low)) != byte(ks) {
				t.Fatalf("ksLow16[%d] contains %04x producing %02x", ks, low, keystreamOf(uint32(low)))
			}
		}
	}
}

// TestRecoverInternalState: given the key2 sequence over a known window plus the
// known plaintext, the full internal state is recovered exactly and decrypts the
// whole stream.
func TestRecoverInternalState(t *testing.T) {
	cases := []struct{ pw, pt string }{
		{"hunter2", "the quick brown fox jumps over the lazy dog"},
		{"S3cr3t!Pass", "0123456789abcdefghijklmnopqrstuvwxyz"},
		{"correct horse battery staple", "ATTACK AT DAWN. bring coffee and donuts."},
	}
	for _, c := range cases {
		c := c
		t.Run(c.pw, func(t *testing.T) {
			plain := []byte(c.pt)
			seq := key2SeqOf(c.pw, plain)

			got, ok := RecoverInternalState(seq, plain)
			if !ok {
				t.Fatalf("RecoverInternalState failed (pw=%q, %d bytes)", c.pw, len(plain))
			}
			if want := NewKeys([]byte(c.pw)); got != want {
				t.Fatalf("recovered keys %+v, want %+v", got, want)
			}

			// The recovered state (before plain[0]) must decrypt the whole ciphertext.
			cipher := make([]byte, len(plain))
			copy(cipher, plain)
			ek := NewKeys([]byte(c.pw))
			ek.Encrypt(cipher)
			dec := append([]byte(nil), cipher...)
			st := got
			st.Decrypt(dec)
			if !bytes.Equal(dec, plain) {
				t.Fatalf("decrypt with recovered keys mismatch:\n got %q\nwant %q", dec, plain)
			}
		})
	}
}

// TestRollBackAcrossHeader models the real ZIP layout: a 12-byte header precedes
// the known plaintext. We recover the mid-stream state, roll back across the
// header (recovering it), and reach the entry's start state.
func TestRollBackAcrossHeader(t *testing.T) {
	password := "Zip!Crypt0"
	header := []byte("ABCDEFGHIJKL") // 12-byte header
	known := []byte("INVOICE-2024-PASTDUE-AMOUNT-4815162342")
	full := append(append([]byte{}, header...), known...)

	cipher := make([]byte, len(full))
	copy(cipher, full)
	ek := NewKeys([]byte(password))
	ek.Encrypt(cipher)

	// key2 sequence over the known (post-header) region.
	allSeq := key2SeqOf(password, full)
	knownSeq := allSeq[len(header):]

	mid, ok := RecoverInternalState(knownSeq, known)
	if !ok {
		t.Fatal("RecoverInternalState failed on post-header window")
	}

	start, recoveredHeader := mid.RollBack(cipher[:len(header)])
	if !bytes.Equal(recoveredHeader, header) {
		t.Fatalf("rolled-back header = %q, want %q", recoveredHeader, header)
	}
	if start != NewKeys([]byte(password)) {
		t.Fatalf("start state = %+v, want fresh keys", start)
	}
	// The start state decrypts the entire stream.
	dec := append([]byte(nil), cipher...)
	start.Decrypt(dec)
	if !bytes.Equal(dec, full) {
		t.Fatalf("full decrypt mismatch:\n got %q\nwant %q", dec, full)
	}
}
