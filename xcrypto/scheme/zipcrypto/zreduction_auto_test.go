package zipcrypto

import (
	"context"
	"testing"
	"time"
)

// TestRecoverKeysCtxCancel proves the compute-heavy in-process attack honors
// context cancellation: with an already-cancelled context it returns promptly
// (after the one-time reduction) instead of grinding through the full keyspace.
func TestRecoverKeysCtxCancel(t *testing.T) {
	plain := []byte("the quick brown fox jumps over the lazy dog 0123456789")
	cipher := append([]byte(nil), plain...)
	ek := NewKeys([]byte("hunter2"))
	ek.Encrypt(cipher)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before starting

	start := time.Now()
	_, ok := RecoverKeysCtx(ctx, plain, cipher)
	if ok {
		t.Fatal("cancelled attack must not report success")
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Fatalf("cancelled attack did not stop promptly: %v", d)
	}
}

// TestAutoPipelineRecovers proves the automatic attack is correct end to end:
// reduceKey2 keeps the true key2, and feeding the true candidate through
// exploreZ + recoverKeysFromZWindow recovers the real keys (verified by a full
// re-encryption inside recoverKeysFromZWindow). A brute over all ~10^5 candidates
// is compute-heavy, so this checks correctness without it.
func TestAutoPipelineRecovers(t *testing.T) {
	for _, pw := range []string{"hunter2", "S3cr3t!"} {
		plain := []byte("the quick brown fox jumps over the lazy dog 0123456789")
		z, ks := trueZandKs(pw, plain)
		bestIdx, best := reduceKey2(ks)
		ksWin := ks[0 : bestIdx+1]

		// locate the true key2 candidate in the reduced set (generate step)
		trueCand, seen := uint32(0), false
		want := z[bestIdx] & 0xfffffc00
		for _, c := range best {
			if c != want {
				continue
			}
			for _, v := range zi2_16Completions(ks[bestIdx], c) {
				if cand := c | (uint32(v) & 0xfffc); cand == z[bestIdx]&0xfffffffc {
					trueCand, seen = cand, true
				}
			}
		}
		if !seen {
			t.Fatalf("pw=%q: reduceKey2 dropped the true key2 candidate", pw)
		}

		wantKeys := NewKeys([]byte(pw))
		ok := false
		exploreZ(ksWin, trueCand, func(zwin []uint32) bool {
			if k, o := recoverKeysFromZWindow(zwin, 0, plain, ks); o && k == wantKeys {
				ok = true
				return true
			}
			return false
		})
		if !ok {
			t.Fatalf("pw=%q: pipeline failed to recover the true keys", pw)
		}
	}
}

// TestRecoverKeysBudgetSafe checks the bounded automatic entry never returns a
// WRONG key: with a tiny budget it will usually not reach the true candidate, but
// whatever it returns, found must imply the keys actually decrypt the plaintext.
func TestRecoverKeysBudgetSafe(t *testing.T) {
	plain := []byte("the quick brown fox jumps over the lazy dog")
	cipher := make([]byte, len(plain))
	copy(cipher, plain)
	ek := NewKeys([]byte("hunter2"))
	ek.Encrypt(cipher)

	keys, found, examined := RecoverKeysBudget(plain, cipher, 3)
	t.Logf("budget=3 examined=%d found=%v", examined, found)
	if found {
		// If it claims success, it must be correct (verify by decrypting).
		dec := append([]byte(nil), cipher...)
		keys.Decrypt(dec)
		if string(dec) != string(plain) {
			t.Fatal("RecoverKeysBudget reported a wrong key")
		}
	}
}
