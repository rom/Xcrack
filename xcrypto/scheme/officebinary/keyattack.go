package officebinary

import (
	"context"
	"crypto/md5" //nolint:gosec // MS-OFFCRYPTO mandates MD5; this attacks legacy files.
	"encoding/binary"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/rom/xcrypto/prim"
)

// The Office 97/2000 RC4 scheme ([MS-OFFCRYPTO] 2.3.6) has a 40-bit bottleneck
// that makes a direct key attack possible — the Elcomsoft "Thunder Tables"
// weakness. The password enters the schedule only as
//
//	trunc = MD5(UTF16LE(password))[:5]            // 40 bits
//
// and everything downstream — the intermediate key, the per-block RC4 keys, the
// verifier, and the whole document ciphertext — is a function of trunc and the
// (public) salt alone:
//
//	trunc2   = MD5( 16 × (trunc || salt) )[:5]
//	blockKey = MD5( trunc2 || LE32(block) )[:16]
//
// So trunc, not the password, is the real secret, and there are only 2^40 of
// them. Sweeping that space with the verifier recovers trunc regardless of how
// long or complex the password was, after which the document decrypts without
// ever learning the password. (The Office XP/2003 "CryptoAPI" RC4 scheme is NOT
// attackable this way even at a 40-bit key size: its intermediate
// H0 = SHA1(salt || password) is 160 bits and every block key derives from it,
// so there is no 40-bit bottleneck to sweep.)

// MaxRC4Trunc is the size of the Office 97/2000 trunc keyspace (2^40).
const MaxRC4Trunc uint64 = 1 << 40

// rc4Trunc returns the 40-bit secret trunc = MD5(UTF16LE(password))[:5] that
// seeds the Office 97/2000 RC4 key schedule.
func rc4Trunc(password []byte) []byte {
	h0 := md5.Sum(prim.UTF16LE(password)) //nolint:gosec
	return append([]byte(nil), h0[:5]...)
}

// rc4Trunc2 derives the salt-mixed intermediate trunc2 from the 40-bit trunc.
// It depends only on (trunc, salt) and is therefore constant across blocks.
func rc4Trunc2(trunc, salt []byte) [5]byte {
	inter := make([]byte, 0, 16*(len(trunc)+len(salt)))
	for i := 0; i < 16; i++ {
		inter = append(inter, trunc...)
		inter = append(inter, salt...)
	}
	h1 := md5.Sum(inter) //nolint:gosec
	var out [5]byte
	copy(out[:], h1[:5])
	return out
}

// rc4BlockKeyFromTrunc2 derives the per-block 128-bit RC4 key from trunc2.
func rc4BlockKeyFromTrunc2(trunc2 [5]byte, block uint32) []byte {
	var buf [9]byte
	copy(buf[:5], trunc2[:])
	binary.LittleEndian.PutUint32(buf[5:], block)
	hfinal := md5.Sum(buf[:]) //nolint:gosec
	return append([]byte{}, hfinal[:16]...)
}

// rc4KeyFromTrunc derives the per-block RC4 key straight from the 40-bit trunc.
func rc4KeyFromTrunc(trunc, salt []byte, block uint32) []byte {
	return rc4BlockKeyFromTrunc2(rc4Trunc2(trunc, salt), block)
}

// VerifyRC4Trunc reports whether the 40-bit trunc secret is correct for the
// Office 97/2000 verifier, without any password. This is the key-attack probe:
// it tests one of the 2^40 possible document keys directly.
func VerifyRC4Trunc(trunc, salt, encVerifier, encVerifierHash []byte) (bool, error) {
	if len(encVerifier) != 16 || len(encVerifierHash) != 16 {
		return false, nil
	}
	key := rc4KeyFromTrunc(trunc, salt, 0)
	buf := append(append([]byte{}, encVerifier...), encVerifierHash...)
	dec, err := prim.RC4(key, buf)
	if err != nil {
		return false, err
	}
	sum := md5.Sum(dec[:16]) //nolint:gosec
	return prim.ConstantTimeEqual(sum[:], dec[16:32]), nil
}

// DecryptRC4Trunc decrypts data with a recovered 40-bit trunc secret (no
// password), rekeying per block from startBlock. trunc2 is computed once.
func DecryptRC4Trunc(trunc, salt, data []byte, blockSize int, startBlock uint32) ([]byte, error) {
	if blockSize <= 0 {
		blockSize = 0x200
	}
	trunc2 := rc4Trunc2(trunc, salt)
	out := make([]byte, 0, len(data))
	block := startBlock
	for off := 0; off < len(data); off += blockSize {
		end := off + blockSize
		if end > len(data) {
			end = len(data)
		}
		dec, err := prim.RC4(rc4BlockKeyFromTrunc2(trunc2, block), data[off:end])
		if err != nil {
			return nil, err
		}
		out = append(out, dec...)
		block++
	}
	return out, nil
}

// RC4KeyAttack sweeps the trunc keyspace indices [start, start+count) for the
// trunc that satisfies the Office 97/2000 verifier, returning it on success.
// The full space is MaxRC4Trunc; callers shard it by (start, count) across hosts
// or an accelerator, and cancel via ctx. Index i maps to the 5 trunc bytes
// little-endian, so [0, MaxRC4Trunc) enumerates every trunc exactly once.
func RC4KeyAttack(ctx context.Context, salt, encVerifier, encVerifierHash []byte, start, count uint64) (trunc []byte, found bool, err error) {
	if len(encVerifier) != 16 || len(encVerifierHash) != 16 || len(salt) == 0 {
		return nil, false, nil
	}
	end := start + count
	if end < start || end > MaxRC4Trunc { // clamp and guard overflow
		end = MaxRC4Trunc
	}

	// Allocation-free inner loop: this runs up to 2^40 times, so every per-iteration
	// heap allocation would be ruinous. The salt-mixing buffer (16×(trunc||salt))
	// is built once and only its 5 trunc bytes per slot change each iteration; the
	// RC4 state lives on the stack; MD5 returns value arrays. No constant-time
	// compare is needed — this is a brute-force sweep, not a secret check.
	saltLen := len(salt)
	slot := 5 + saltLen
	inter := make([]byte, 16*slot)
	for s := 0; s < 16; s++ {
		copy(inter[s*slot+5:], salt) // salt bytes are constant across iterations
	}
	var ev [32]byte
	copy(ev[:16], encVerifier)
	copy(ev[16:], encVerifierHash)
	var dec [32]byte
	var state [256]byte

	for i := start; i < end; i++ {
		if i&0xFFFFF == 0 && ctx != nil {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			default:
			}
		}
		t0, t1, t2, t3, t4 := byte(i), byte(i>>8), byte(i>>16), byte(i>>24), byte(i>>32)
		for s := 0; s < 16; s++ {
			b := s * slot
			inter[b], inter[b+1], inter[b+2], inter[b+3], inter[b+4] = t0, t1, t2, t3, t4
		}
		trunc2 := md5.Sum(inter) //nolint:gosec
		var kb [9]byte
		copy(kb[:5], trunc2[:5]) // kb[5:9] stays zero == LE32(block 0)
		key := md5.Sum(kb[:])    //nolint:gosec // the 16-byte RC4 key

		// RC4 keystream (KSA + PRGA) over the 32-byte verifier, in place, no alloc.
		for k := 0; k < 256; k++ {
			state[k] = byte(k)
		}
		j := 0
		for k := 0; k < 256; k++ {
			j = (j + int(state[k]) + int(key[k&15])) & 0xff
			state[k], state[j] = state[j], state[k]
		}
		a, bb := 0, 0
		for n := 0; n < 32; n++ {
			a = (a + 1) & 0xff
			bb = (bb + int(state[a])) & 0xff
			state[a], state[bb] = state[bb], state[a]
			dec[n] = ev[n] ^ state[(int(state[a])+int(state[bb]))&0xff]
		}
		if md5.Sum(dec[:16]) == *(*[16]byte)(dec[16:32]) { //nolint:gosec
			return []byte{t0, t1, t2, t3, t4}, true, nil
		}
	}
	return nil, false, nil
}

// RC4KeyAttackParallel runs RC4KeyAttack over [start, start+count) across
// `workers` goroutines (0 => GOMAXPROCS), stopping as soon as one finds the
// trunc. It is the practical CPU driver for the 2^40 sweep; the single-range
// RC4KeyAttack remains the unit for distributed/accelerated sharding.
func RC4KeyAttackParallel(ctx context.Context, salt, encVerifier, encVerifierHash []byte, start, count uint64, workers int) (trunc []byte, found bool, err error) {
	if len(encVerifier) != 16 || len(encVerifierHash) != 16 || len(salt) == 0 {
		return nil, false, nil
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	end := start + count
	if end < start || end > MaxRC4Trunc {
		end = MaxRC4Trunc
	}
	total := end - start
	if total == 0 {
		return nil, false, nil
	}
	if uint64(workers) > total {
		workers = int(total)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		result   []byte
		gotHit   atomic.Bool
		firstErr error
	)
	chunk := total / uint64(workers)
	rem := total % uint64(workers)
	cur := start
	for w := 0; w < workers; w++ {
		n := chunk
		if uint64(w) < rem {
			n++
		}
		if n == 0 {
			continue
		}
		ws, wc := cur, n
		cur += n
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr, ok, e := RC4KeyAttack(ctx, salt, encVerifier, encVerifierHash, ws, wc)
			if e != nil {
				mu.Lock()
				if firstErr == nil && e != context.Canceled {
					firstErr = e
				}
				mu.Unlock()
				return
			}
			if ok {
				mu.Lock()
				if !gotHit.Swap(true) {
					result = tr
				}
				mu.Unlock()
				cancel() // signal the other workers to stop
			}
		}()
	}
	wg.Wait()
	if gotHit.Load() {
		return result, true, nil
	}
	return nil, false, firstErr
}
