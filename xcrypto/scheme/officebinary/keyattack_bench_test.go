package officebinary

import (
	"context"
	"testing"
)

// BenchmarkRC4KeyAttack sweeps a fixed window that does not contain the key, so
// it scans fully — measuring the per-candidate cost and allocation behaviour of
// the 2^40 inner loop. Report with -benchmem; allocs/op should be ~0.
func BenchmarkRC4KeyAttack(b *testing.B) {
	const window = 1 << 14
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Start high enough that the real "password1" trunc is not in-window.
		RC4KeyAttack(context.Background(), katSalt, katVerify, katVHash, 1<<32, window)
	}
}
