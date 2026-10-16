package zipcrypto

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// Zreduction — the front half of the Biham–Kocher attack: recover the key2 (Z)
// value from the keystream alone, with no password. Combined with the verified
// back half (RecoverInternalState in knownplaintext.go) this makes the
// known-plaintext attack fully automatic: given enough known plaintext and the
// matching ciphertext, RecoverKeys recovers the whole internal state.
//
// It is implemented from the algorithm (not copied from any implementation),
// using this package's own primitives, and each helper is checked against a real
// key schedule in the tests. The idea: a key2 value's keystream byte depends only
// on its low 16 bits, and consecutive key2 values are linked by a CRC32 step.
// Representing a candidate by its top 22 bits (key2[10,32)) lets the CRC relation
// be followed WITHOUT the low 2 bits (they fall off the bottom), while the
// keystream still pins bits [2,16). Propagating the keystream constraints across
// the window shrinks the candidate set dramatically (the pruning the naive
// single-pass recovery lacked).

// contiguousWindow is how many leading bytes of the known plaintext must be
// contiguous; the reduction propagates constraints across them.
const contiguousWindow = 8

// ksByHi[k][hi6] holds every 16-bit low value of key2 that produces keystream
// byte k and whose bits [10,16) equal hi6. It answers, for a candidate known only
// down to bit 10, which bit[2,10) completions keep it keystream-consistent.
var ksByHi [256][64][]uint16

func init() {
	for k := 0; k < 256; k++ {
		for _, v := range ksLow16[k] {
			hi6 := (v >> 10) & 0x3f
			ksByHi[k][hi6] = append(ksByHi[k][hi6], v)
		}
	}
}

// hasZi reports whether some bit[2,10) completion of z (known at bits [10,32))
// yields a low-16 value producing keystream byte k.
func hasZi(k byte, z uint32) bool {
	return len(ksByHi[k][(z>>10)&0x3f]) > 0
}

// zi2_16Completions returns the bits[2,16) masks (into the low 16 bits) that make
// z (known at bits [10,32)) keystream-consistent with k. Each returned mask is
// OR-ed into z to realise a bits[2,32) candidate.
func zi2_16Completions(k byte, z uint32) []uint16 {
	return ksByHi[k][(z>>10)&0x3f]
}

// msbProdFiber3[t] holds every byte x whose msb(x*multInv) is within 1 of t,
// i.e. in {t-1, t, t+1}. It turns "which low byte of key1 bridges this msb gap"
// from a 256-way scan into a short lookup — the speedup that makes the key1
// enumeration ~2^16 instead of ~2^24 per candidate.
var msbProdFiber3 [256][]byte

// msbProdFiber2[t] holds every byte x whose msb(x*multInv) is t or t-1. It drives
// the two-step key1 roll-back (ffy), filtering the low byte at every level so the
// search never fans out 256-wide.
var msbProdFiber2 [256][]byte

// multInvStep == multInv*256 as a runtime value (a constant expression would
// overflow uint32 at compile time, so it is built from a non-constant var).
var (
	multInvRT   = uint32(multInvConst)
	multInvStep = multInvRT << 8
)

func init() {
	prodinv := uint32(0)
	for x := 0; x < 256; x++ {
		m := byte(prodinv >> 24)
		// fiber3: x lands in buckets {m-1, m, m+1} (a ±1 msb window).
		msbProdFiber3[(m-1)&0xff] = append(msbProdFiber3[(m-1)&0xff], byte(x))
		msbProdFiber3[m] = append(msbProdFiber3[m], byte(x))
		msbProdFiber3[(m+1)&0xff] = append(msbProdFiber3[(m+1)&0xff], byte(x))
		// fiber2: x lands in buckets {m, m+1}, so msbProdFiber2[t] == {x :
		// msb(x*multInv) in {t-1, t}} — the tight set the two-step roll-back needs.
		msbProdFiber2[m] = append(msbProdFiber2[m], byte(x))
		msbProdFiber2[(m+1)&0xff] = append(msbProdFiber2[(m+1)&0xff], byte(x))
		prodinv += multInvConst
	}
}

// ywork holds the per-window key1/key0 search state. Using a struct with direct
// methods (rather than closures) keeps the ~2^16-per-window recursion a sequence
// of direct, inlinable calls with no closure-environment indirection — the main
// constant-factor win over the previous version.
type ywork struct {
	zwin   []uint32
	plain  []byte
	ks     []byte
	msbY   []byte
	y      []uint32
	lsbX   []byte
	base   int
	top    int
	result Keys
}

var yworkPool = sync.Pool{New: func() any { return &ywork{} }}

// recoverKeysFromZWindow recovers the full internal state from a reconstructed
// 8-index key2 window and the known plaintext. It enumerates key1 at the window
// top with the fiber (fast), rolls key1 backward to recover four consecutive low
// bytes of key0, rebuilds a full key0 word (the verified reconstruction), then
// validates by re-encrypting the entire known plaintext. On success it returns
// the internal Keys as of just before plain[0]. zwin[w] is key2 at global index
// base+w.
func recoverKeysFromZWindow(zwin []uint32, base int, plain, ks []byte) (Keys, bool) {
	W := len(zwin)
	top := W - 1
	if base+top >= len(plain) || base < 0 || W < 5 {
		return Keys{}, false
	}
	w := yworkPool.Get().(*ywork)
	defer yworkPool.Put(w)
	w.zwin, w.plain, w.ks, w.base, w.top = zwin, plain, ks, base, top
	w.msbY = ensure(w.msbY, W)
	w.y = ensureU32(w.y, W)
	w.lsbX = ensure(w.lsbX, W)
	// msb of key1 at window index i (global base+i), for i in [1,top].
	for i := 1; i < W; i++ {
		w.msbY[i] = byte(crc32inv(zwin[i], 0) ^ zwin[i-1])
	}

	// Enumerate full key1 at the window top: top byte known, middle 16 bits looped,
	// low byte supplied by the fiber and checked against an exact range.
	m7 := w.msbY[top]
	m6 := w.msbY[top-1]
	y7base := uint32(m7) << 24
	P0 := (y7base - 1) * multInvConst
	step := multInvStep
	const maxYDiff = (1 << 24) + 256 // lower24(y6)+lsb(x) is always below this
	for mid := uint32(0); mid < (1 << 16); mid++ {
		target := m6 - byte(P0>>24)
		for _, low := range msbProdFiber3[target] {
			if P0+uint32(low)*multInvConst-(uint32(m6)<<24) < maxYDiff {
				w.y[top] = y7base | (mid << 8) | uint32(low)
				if w.rec(top) {
					return w.result, true
				}
			}
		}
		P0 += step
	}
	return Keys{}, false
}

// rec rolls key1 backward from level using the two-step fiber (ffy), which pins
// the candidate low byte of key0 at EVERY level to the ~2 values consistent with
// msb(key1) two indices down, then keeps those matching this level's msb(key1).
// The search therefore never fans out 256-wide — the single change that drops the
// per-window cost from ~2^24 buildAndVerify calls to ~2^16. When four consecutive
// low bytes of key0 are known it hands off to buildAndVerify.
func (w *ywork) rec(level int) bool {
	if level == w.top-4 {
		if keys, ok := w.buildAndVerify(); ok {
			w.result = keys
			return true
		}
		return false
	}
	P := (w.y[level] - 1) * multInvConst // fy = y[level-1] + lsb(x[level])
	want := byte(w.msbY[level-1])
	if level >= 3 {
		// Two-step fiber. ffy = (fy-1)*multInv = y[level-2] + lsb(x[level-1]) +
		// lsb(x[level])*multInv, so msb(ffy)-msb(y[level-2]) pins msb(lsb(x[level])*
		// multInv) to {t-1, t} (the top-byte carry of the two low addends is 0 or 1).
		// msbProdFiber2[t] lists exactly those low bytes; the msb(key1[level-1]) test
		// keeps the survivors. ~2 candidates per level instead of ~128.
		ffy := (P - 1) * multInvConst
		target := byte(ffy>>24) - w.msbY[level-2]
		for _, a := range msbProdFiber2[target] {
			yim1 := P - uint32(a)
			if byte(yim1>>24) != want {
				continue
			}
			w.y[level-1] = yim1
			w.lsbX[level] = a
			if w.rec(level - 1) {
				return true
			}
		}
		return false
	}
	// Shallow window (no key1 two indices down to drive the fiber): fall back to an
	// exact one-step scan selecting lsb(x[level]) by this level's msb(key1). Only
	// reachable for tiny windows; the real attack always uses windows >= 9.
	band := byte(P >> 24)
	lowbits := P & 0xffffff
	switch want {
	case band:
		hi := lowbits
		if hi > 255 {
			hi = 255
		}
		for a := uint32(0); a <= hi; a++ {
			w.y[level-1] = P - a
			w.lsbX[level] = byte(a)
			if w.rec(level - 1) {
				return true
			}
		}
	case band - 1:
		for a := lowbits + 1; a <= 255; a++ {
			w.y[level-1] = P - a
			w.lsbX[level] = byte(a)
			if w.rec(level - 1) {
				return true
			}
		}
	}
	return false
}

// buildAndVerify rebuilds a full key0 from the four consecutive recovered low
// bytes, assembles the state, rolls it to plain[0], and re-encrypts to confirm.
func (w *ywork) buildAndVerify() (Keys, bool) {
	w0 := w.top - 3
	k := w.lsbX[w0] ^ w.plain[w.base+w0]
	k1 := w.lsbX[w0+1] ^ w.plain[w.base+w0+1]
	k2 := w.lsbX[w0+2] ^ w.plain[w.base+w0+2]
	// byte1..3 of key0 at w0 (see the verified reconstruction derivation).
	b1 := w.lsbX[w0+1] ^ byte(crcTab[k])
	b1n := w.lsbX[w0+2] ^ byte(crcTab[k1])
	b2n := w.lsbX[w0+3] ^ byte(crcTab[k2])
	b2 := b1n ^ byte(crcTab[k]>>8)
	b1nn := b2n ^ byte(crcTab[k1]>>8)
	b3 := b1nn ^ byte(crcTab[k]>>16)
	x := uint32(w.lsbX[w0]) | uint32(b1)<<8 | uint32(b2)<<16 | uint32(b3)<<24

	state := Keys{k0: x, k1: w.y[w0], k2: w.zwin[w0]} // state before plain[base+w0]
	// Verify FORWARD from w0 first. A wrong candidate's key2 diverges after one
	// update, so this rejects almost all candidates within two keystream bytes —
	// far cheaper than rolling the state back to plain[0] first (which the earlier
	// version did for every candidate). Only a surviving candidate is rolled back.
	chk := state
	for i := w.base + w0; i < len(w.plain); i++ {
		if chk.streamByte() != w.ks[i] {
			return Keys{}, false
		}
		chk.update(w.plain[i])
	}
	// Forward half holds; roll back to plain[0], validating the backward half too.
	for g := w.base + w0; g > 0; g-- {
		state = invStep(state, w.plain[g-1])
		if state.streamByte() != w.ks[g-1] {
			return Keys{}, false
		}
	}
	return state, true
}

func ensure(b []byte, n int) []byte {
	if cap(b) >= n {
		return b[:n]
	}
	return make([]byte, n)
}

func ensureU32(b []uint32, n int) []uint32 {
	if cap(b) >= n {
		return b[:n]
	}
	return make([]uint32, n)
}

// RecoverKeys runs the fully automatic known-plaintext attack: given the known
// plaintext and matching ciphertext (plain[i] ^ cipher[i] is the keystream), it
// recovers the internal state with no password and no external reducer, and
// returns the Keys as of just before plain[0]. From there RollBack reaches the
// entry start and decrypts everything.
//
// Performance note. This is a correct, self-contained pure-Go implementation of
// the Biham–Kocher attack. It is COMPUTE-HEAVY: the keystream leaves ~10^5 key2
// candidates and the per-candidate key1 enumeration is ~2^16. The candidate
// search runs across all CPU cores, so wall-clock time scales down with core
// count — tens of minutes on a many-core server, longer on a small box
// (optimized C++ tools such as bkcrack do the same work in minutes). More known
// plaintext does not shrink the candidate set, so for time-sensitive recovery on
// the heavy backend prefer offloading to an external/GPU engine via the
// challenge-export bridge. Use RecoverKeysBudget to bound the effort.
func RecoverKeys(plain, cipher []byte) (Keys, bool) {
	k, ok, _ := RecoverKeysBudget(plain, cipher, 0)
	return k, ok
}

// RecoverKeysBudget is RecoverKeys with a cap on the number of key2 candidates
// examined (0 = unlimited). It also returns how many were examined, so a caller
// can report progress or resume with a larger budget.
func RecoverKeysBudget(plain, cipher []byte, budget int) (Keys, bool, int) {
	if len(plain) != len(cipher) || len(plain) < MinKnownPlaintext {
		return Keys{}, false, 0
	}
	ks := make([]byte, len(plain))
	for i := range plain {
		ks[i] = plain[i] ^ cipher[i]
	}
	return recoverAuto(plain, ks, budget)
}

// recoverAuto runs the full automatic attack: reduce the key2 candidates, and
// for each, reconstruct the key2 window and attempt full key recovery. budget
// caps the number of generate candidates examined (0 = unlimited); it returns the
// number examined so callers can report progress. On success the Keys are the
// internal state just before plain[0].
func recoverAuto(plain, ks []byte, budget int) (Keys, bool, int) {
	n := len(ks)
	if n < contiguousWindow+1 {
		return Keys{}, false, 0
	}
	bestIdx, best := reduceKey2(ks)
	if bestIdx < 4 {
		return Keys{}, false, 0
	}
	ksWin := ks[0 : bestIdx+1] // reconstruct key2 over [0, bestIdx]

	// The candidates are independent, so split them across workers. Each worker
	// runs the stateless exploreZ + recoverKeysFromZWindow on its slice; the first
	// match stops the rest. This scales recovery with core count.
	workers := runtime.NumCPU()
	if workers < 1 {
		workers = 1
	}
	var (
		mu       sync.Mutex
		result   Keys
		found    atomic.Bool
		examined atomic.Int64
		wg       sync.WaitGroup
	)
	chunk := (len(best) + workers - 1) / workers
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := lo + chunk
		if lo >= len(best) {
			break
		}
		if hi > len(best) {
			hi = len(best)
		}
		wg.Add(1)
		go func(sub []uint32) {
			defer wg.Done()
			for _, zi10 := range sub {
				if found.Load() {
					return
				}
				for _, v := range zi2_16Completions(ks[bestIdx], zi10) {
					if found.Load() {
						return
					}
					if nn := examined.Add(1); budget > 0 && nn > int64(budget) {
						return
					}
					cand := zi10 | (uint32(v) & 0xfffc)
					exploreZ(ksWin, cand, func(zwin []uint32) bool {
						if keys, ok := recoverKeysFromZWindow(zwin, 0, plain, ks); ok {
							mu.Lock()
							result = keys
							mu.Unlock()
							found.Store(true)
							return true
						}
						return false
					})
				}
			}
		}(best[lo:hi])
	}
	wg.Wait()
	return result, found.Load(), int(examined.Load())
}

// reduceKey2 propagates keystream constraints across the window to shrink the
// candidate set for key2[10,32). It returns the index whose candidate set yields
// the fewest full key2[2,32) candidates, and that set (each a key2[10,32) value).
func reduceKey2(ks []byte) (bestIdx int, best []uint32) {
	n := len(ks)
	L := n - 1

	// Initial set at the last index: every 22-bit top that is keystream-possible.
	var S []uint32
	for h := uint32(0); h < (1 << 22); h++ {
		z := h << 10
		if hasZi(ks[L], z) {
			S = append(S, z)
		}
	}
	bestIdx, best = L, S
	bestMetric := fullCount(ks[L], S)

	floor := contiguousWindow
	if floor > n-1 {
		floor = n - 1
	}
	for i := L; i > floor; i-- {
		present := make([]bool, 1<<22)
		var newS []uint32
		for _, zi10 := range S {
			for _, v := range zi2_16Completions(ks[i], zi10) {
				zi := zi10 | (uint32(v) & 0xfffc)
				zim1 := getZim1_10_32(zi)
				if !hasZi(ks[i-1], zim1) {
					continue
				}
				idx := zim1 >> 10
				if present[idx] {
					continue
				}
				present[idx] = true
				newS = append(newS, zim1)
			}
		}
		S = newS
		if m := fullCount(ks[i-1], S); m < bestMetric {
			bestMetric, bestIdx, best = m, i-1, S
		}
	}
	return bestIdx, best
}

// fullCount is the number of full key2[2,32) candidates a set expands to at the
// given keystream byte — the work the key-recovery back half would do.
func fullCount(k byte, set []uint32) int {
	n := 0
	for _, z := range set {
		n += len(zi2_16Completions(k, z))
	}
	return n
}

// exploreZ reconstructs the full (32-bit) key2 values over an 8-index window
// ending at the candidate, given the window's keystream bytes. zTop is a
// key2[2,32) candidate for window position 7 (its low 2 bits are unknown and
// enumerated). For each fully consistent window it calls emit(zwin) where
// zwin[w] is the full key2 at window position w; emit returns true to stop.
//
// Backward step: z_{w-1} has bits [8,32) fixed by crc32inv(z_w, 0); its low byte
// comes from a keystream-table entry matching those fixed bits [8,16). The low 2
// bits of each z are resolved here (they are keystream-irrelevant but feed the
// next CRC step, so the step after prunes wrong choices).
func exploreZ(ksWin []byte, zTop uint32, emit func(zwin []uint32) bool) bool {
	zwin := make([]uint32, len(ksWin))
	top := len(ksWin) - 1
	var dfs func(w int) bool
	dfs = func(w int) bool {
		if w == 0 {
			return emit(zwin) // zwin[0..top] all set
		}
		zi := zwin[w]
		next := crc32inv(zi, 0) // bits [8,32) of z_{w-1}; low byte is next^b
		hi8 := byte(next >> 8)  // bits [8,16) of z_{w-1}, fixed
		for _, v := range ksLow16[ksWin[w-1]] {
			if byte(v>>8) != hi8 {
				continue
			}
			zwin[w-1] = (next & 0xffffff00) | uint32(v&0xff)
			if dfs(w - 1) {
				return true
			}
		}
		return false
	}
	// Enumerate the 2 keystream-irrelevant low bits of the top key2, then recurse.
	for lo := uint32(0); lo < 4; lo++ {
		zwin[top] = (zTop &^ 3) | lo
		if dfs(top) {
			return true
		}
	}
	return false
}

// getZim1_10_32 returns bits [10,32) of key2 at index i-1 given key2 at index i
// known to bits [2,32) (low 2 bits zero). Derivation: z_i = crc32(z_{i-1}, b);
// crc32inv(z_i,0) gives z_{i-1} correct in bits [8,32) (b only touches bits
// [0,8)); and bits [10,32) of crc32inv(z_i,0) depend only on z_i bits [2,24) and
// the top byte, all within the known [2,32) — so the low 2 bits never enter.
func getZim1_10_32(zi uint32) uint32 {
	return ((zi << 8) ^ crcInvTab[zi>>24]) & 0xfffffc00
}
