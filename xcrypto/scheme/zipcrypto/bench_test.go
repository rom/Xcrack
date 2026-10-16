package zipcrypto

import "testing"

// BenchmarkPerWindow measures the cost of one key-recovery over a wrong z-window
// (the dominant per-candidate cost in the full attack).
func BenchmarkPerWindow(b *testing.B) {
	plain := []byte("the quick brown fox jumps over the lazy dog 0123456789")
	z, ks := trueZandKs("hunter2", plain)
	bestIdx, _ := reduceKey2(ks)
	win := append([]uint32(nil), z[0:bestIdx+1]...)
	win[bestIdx] ^= 0x40000000 // make it a wrong window (exhausts the search)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		recoverKeysFromZWindow(win, 0, plain, ks)
	}
}
