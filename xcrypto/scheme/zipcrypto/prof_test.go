package zipcrypto

import "testing"

// BenchmarkReduceKey2 isolates the one-time front-half reduction.
func BenchmarkReduceKey2(b *testing.B) {
	plain := []byte("the quick brown fox jumps over the lazy dog 0123456789")
	_, ks := trueZandKs("hunter2", plain)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reduceKey2(ks)
	}
}

// BenchmarkBudgetedAttack runs the full automatic attack over a bounded number
// of candidates, so a CPU profile shows the real per-candidate hot path
// (exploreZ + recoverKeysFromZWindow) rather than one-time setup.
func BenchmarkBudgetedAttack(b *testing.B) {
	plain := []byte("the quick brown fox jumps over the lazy dog 0123456789")
	cipher := append([]byte(nil), plain...)
	ek := NewKeys([]byte("hunter2"))
	ek.Encrypt(cipher)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RecoverKeysBudget(plain, cipher, 400)
	}
}
