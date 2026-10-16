package zipcrypto

import "testing"

// trueZandKs returns the true key2 (Z) sequence and keystream for a password.
func trueZandKs(password string, plain []byte) (z []uint32, ks []byte) {
	k := NewKeys([]byte(password))
	z = make([]uint32, len(plain))
	ks = make([]byte, len(plain))
	for i := range plain {
		z[i] = k.k2
		ks[i] = k.streamByte()
		k.update(plain[i])
	}
	return
}

// TestZreductionHelpers validates the reduction primitives against a real key
// schedule: the inverse-CRC relation, the keystream existence check, and that the
// true low-16 value is among the completions.
func TestZreductionHelpers(t *testing.T) {
	z, ks := trueZandKs("hunter2", []byte("the quick brown fox jumps over the lazy dog"))
	for i := 1; i < len(z); i++ {
		got := getZim1_10_32(z[i] & 0xfffffffc)
		if got != (z[i-1] & 0xfffffc00) {
			t.Fatalf("getZim1_10_32 at i=%d: got %08x want %08x (z[i]=%08x z[i-1]=%08x)",
				i, got, z[i-1]&0xfffffc00, z[i], z[i-1])
		}
	}
	for i := range z {
		if !hasZi(ks[i], z[i]) {
			t.Fatalf("hasZi false for the true z[%d]=%08x ks=%02x", i, z[i], ks[i])
		}
		// The true low-16 must be among the completions for its own bits[10,16).
		want := uint16(z[i] & 0xffff)
		found := false
		for _, v := range zi2_16Completions(ks[i], z[i]) {
			if v == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("true low16 %04x not among completions at i=%d", want, i)
		}
	}
}
