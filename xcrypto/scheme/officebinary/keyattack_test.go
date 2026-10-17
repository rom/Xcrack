package officebinary

import (
	"bytes"
	"context"
	"testing"
)

// truncIndex maps a 5-byte trunc to its little-endian sweep index, the inverse
// of the mapping RC4KeyAttack uses.
func truncIndex(trunc []byte) uint64 {
	return uint64(trunc[0]) | uint64(trunc[1])<<8 | uint64(trunc[2])<<16 |
		uint64(trunc[3])<<24 | uint64(trunc[4])<<32
}

// TestVerifyRC4TruncMatchesPassword confirms the password-free trunc verifier
// agrees with the password verifier on the known-answer vector: the trunc
// derived from the real password passes, and neighbouring truncs fail.
func TestVerifyRC4TruncMatchesPassword(t *testing.T) {
	trunc := rc4Trunc([]byte("password1"))
	ok, err := VerifyRC4Trunc(trunc, katSalt, katVerify, katVHash)
	if err != nil || !ok {
		t.Fatalf("VerifyRC4Trunc(real trunc) = %v, %v; want true", ok, err)
	}
	// Cross-check against the password verifier.
	if pwOK, _ := VerifyRC4([]byte("password1"), katSalt, katVerify, katVHash); !pwOK {
		t.Fatal("password verifier disagrees with trunc verifier")
	}
	bad := append([]byte(nil), trunc...)
	bad[0] ^= 0x01
	if ok, _ := VerifyRC4Trunc(bad, katSalt, katVerify, katVHash); ok {
		t.Fatal("VerifyRC4Trunc accepted a wrong trunc")
	}
}

// TestDecryptRC4TruncEqualsPassword proves the recovered key decrypts the
// document identically to the password path (no password needed).
func TestDecryptRC4TruncEqualsPassword(t *testing.T) {
	trunc := rc4Trunc([]byte("password1"))
	plain := bytes.Repeat([]byte("legacy office secret "), 100) // spans multiple blocks
	enc, err := DecryptRC4([]byte("password1"), katSalt, plain, 0x200)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptRC4Trunc(trunc, katSalt, enc, 0x200, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, plain) {
		t.Fatal("trunc decryption does not match password decryption")
	}
}

// TestRC4KeyAttackRecovers sweeps a small window containing the real trunc and
// confirms the attack recovers a key that passes the verifier. This exercises
// the exact index->trunc mapping and verifier used by the full 2^40 sweep,
// without running all of it.
func TestRC4KeyAttackRecovers(t *testing.T) {
	real := rc4Trunc([]byte("password1"))
	idx := truncIndex(real)
	start := idx
	if start >= 5 {
		start -= 5
	} else {
		start = 0
	}
	count := idx - start + 6 // window straddles idx

	got, found, err := RC4KeyAttack(context.Background(), katSalt, katVerify, katVHash, start, count)
	if err != nil || !found {
		t.Fatalf("RC4KeyAttack found=%v err=%v", found, err)
	}
	if ok, _ := VerifyRC4Trunc(got, katSalt, katVerify, katVHash); !ok {
		t.Fatalf("recovered trunc %x does not verify", got)
	}
	if !bytes.Equal(got, real) {
		t.Fatalf("recovered trunc %x != expected %x", got, real)
	}

	// Parallel driver recovers the same key.
	gotP, foundP, err := RC4KeyAttackParallel(context.Background(), katSalt, katVerify, katVHash, start, count, 4)
	if err != nil || !foundP {
		t.Fatalf("RC4KeyAttackParallel found=%v err=%v", foundP, err)
	}
	if !bytes.Equal(gotP, real) {
		t.Fatalf("parallel recovered %x != expected %x", gotP, real)
	}
}

// TestRC4KeyAttackMiss returns no hit for a window that excludes the key.
func TestRC4KeyAttackMiss(t *testing.T) {
	real := rc4Trunc([]byte("password1"))
	idx := truncIndex(real)
	// A window far from idx (guard both directions).
	start := idx + 1000
	if idx < 2000 {
		start = idx + 1000
	}
	if _, found, err := RC4KeyAttack(context.Background(), katSalt, katVerify, katVHash, start, 100); found || err != nil {
		t.Fatalf("expected miss; got found=%v err=%v", found, err)
	}
}

// TestRC4KeyAttackCancel honours a cancelled context promptly.
func TestRC4KeyAttackCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// start=0 forces the per-window cancellation check on the first iteration.
	_, found, err := RC4KeyAttack(ctx, katSalt, katVerify, katVHash, 0, MaxRC4Trunc)
	if found {
		t.Fatal("cancelled attack reported a hit")
	}
	if err != context.Canceled {
		t.Fatalf("err = %v; want context.Canceled", err)
	}
}

// TestRC4KeyAttackBounds rejects malformed inputs without scanning.
func TestRC4KeyAttackBounds(t *testing.T) {
	if _, found, _ := RC4KeyAttack(context.Background(), nil, katVerify, katVHash, 0, 10); found {
		t.Fatal("empty salt should not find")
	}
	if _, found, _ := RC4KeyAttack(context.Background(), katSalt, katVerify[:8], katVHash, 0, 10); found {
		t.Fatal("short verifier should not find")
	}
}
