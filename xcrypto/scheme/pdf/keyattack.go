package pdf

import (
	"context"
	"crypto/md5" //nolint:gosec // the PDF Standard Security Handler mandates MD5; this attacks legacy files.
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/rom/xcrypto/prim"
)

// The PDF Standard Security Handler's 40-bit RC4 scheme (V1/R2, and any R3/R4
// document whose file-key /Length is 40 bits) has the same key-size bottleneck
// that makes the Office 97/2000 attack possible. The password enters the
// handler only through the MD5 that derives the file key:
//
//	fileKey = MD5( pad(pw) || O || P || ID [|| 0xffffffff] )[:5]      // 40 bits
//
// and the user-password verifier /U, every per-object key, and the whole
// document ciphertext are functions of that 5-byte fileKey alone:
//
//	R2:     U = RC4(fileKey, pad)                                     // 32 bytes
//	R3/R4:  U = RC4(fileKey, MD5(pad||ID)); then 19 XOR-RC4 rounds    // 16 bytes
//
// So fileKey, not the password, is the real secret, and there are only 2^40 of
// them. Sweeping that space against /U recovers fileKey regardless of how long
// or complex the password was, after which every string and stream decrypts
// (ObjectKey/DecryptData) without ever learning the password. The sweep needs
// only the public /U, /ID and revision — not /O, /P, or the password. It does
// not apply to 128-bit RC4 (R3/R4 with /Length 128) nor to AESV2/AESV3, whose
// keys are 128/256 bits with no shortcut.

// MaxRC4FileKey is the size of the 40-bit PDF file-key space (2^40).
const MaxRC4FileKey uint64 = 1 << 40

// RC4KeyAttackable reports whether h is a 40-bit RC4 handler — i.e. whether the
// direct file-key sweep below applies. 128-bit RC4 and the AES ciphers are not
// attackable this way, and neither are the R5/R6 (AES-256) handlers.
func (h *Handler) RC4KeyAttackable() bool {
	if h.Cipher != CipherRC4 || h.R < 2 || h.R >= 5 || h.keyLenBytes() != 5 {
		return false
	}
	if h.R == 2 {
		return len(h.U) >= 32
	}
	return len(h.U) >= 16
}

// VerifyFileKey reports whether the 5-byte file key satisfies the user-password
// verifier /U, with no password. This is the key-attack probe: it tests one of
// the 2^40 candidate document keys directly. It handles R2 (32-byte /U) and
// R3/R4 (16-byte /U) alike.
func (h *Handler) VerifyFileKey(key []byte) bool {
	u := h.computeU(key)
	if h.R == 2 {
		return len(h.U) >= 32 && prim.ConstantTimeEqual(u, h.U[:32])
	}
	return len(h.U) >= 16 && prim.ConstantTimeEqual(u[:16], h.U[:16])
}

// RC4KeyAttackParams returns the parameters an external or accelerated sweep
// needs to reproduce the /U verifier without this package: the RC4 input buffer,
// the number of XOR-RC4 rounds (round r is keyed by fileKey XOR r), the compare
// length, and the expected /U prefix. It mirrors computeU exactly —
//
//	R2:     input = pad (32 bytes),      rounds = 1,  cmpLen = 32
//	R3/R4:  input = MD5(pad || ID) (16), rounds = 20, cmpLen = 16
//
// ok is false when the document is not 40-bit-RC4 attackable.
func (h *Handler) RC4KeyAttackParams() (input []byte, rounds, cmpLen int, u []byte, ok bool) {
	if !h.RC4KeyAttackable() {
		return nil, 0, 0, nil, false
	}
	if h.R == 2 {
		return append([]byte(nil), pad...), 1, 32, append([]byte(nil), h.U[:32]...), true
	}
	m := md5.New() //nolint:gosec
	m.Write(pad)
	m.Write(h.ID)
	return m.Sum(nil), 20, 16, append([]byte(nil), h.U[:16]...), true
}

// RC4KeyAttack sweeps the 40-bit file-key indices [start, start+count) for the
// key that satisfies /U, returning it on success. The full space is
// MaxRC4FileKey; callers shard it by (start, count) across hosts or cores and
// cancel via ctx. Index i maps to the 5 key bytes little-endian, so
// [0, MaxRC4FileKey) enumerates every key exactly once.
func (h *Handler) RC4KeyAttack(ctx context.Context, start, count uint64) (key []byte, found bool, err error) {
	if !h.RC4KeyAttackable() {
		return nil, false, nil
	}
	end := start + count
	if end < start || end > MaxRC4FileKey { // clamp and guard overflow
		end = MaxRC4FileKey
	}
	if h.R == 2 {
		return h.rc4KeyAttackR2(ctx, start, end)
	}
	return h.rc4KeyAttackGeneral(ctx, start, end)
}

// rc4KeyAttackR2 is the allocation-free hot path for the common V1/R2 case:
// /U = RC4(fileKey, pad), so each candidate is a single RC4 schedule over the
// 32-byte padding string, compared to /U and abandoned on the first mismatched
// byte (true for 255/256 of candidates at byte 0). The RC4 state lives on the
// stack; nothing is allocated per iteration.
func (h *Handler) rc4KeyAttackR2(ctx context.Context, start, end uint64) ([]byte, bool, error) {
	var u [32]byte
	copy(u[:], h.U[:32])
	var state [256]byte
	var key [5]byte
	for i := start; i < end; i++ {
		if i&0xFFFFF == 0 && ctx != nil {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			default:
			}
		}
		key[0], key[1], key[2], key[3], key[4] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24), byte(i>>32)
		// RC4 KSA with the 5-byte key (ki cycles 0..4 without a division).
		for k := 0; k < 256; k++ {
			state[k] = byte(k)
		}
		j, ki := 0, 0
		for k := 0; k < 256; k++ {
			j = (j + int(state[k]) + int(key[ki])) & 0xff
			state[k], state[j] = state[j], state[k]
			if ki++; ki == 5 {
				ki = 0
			}
		}
		// PRGA over the 32-byte pad, comparing to /U, breaking on first miss.
		a, b := 0, 0
		match := true
		for n := 0; n < 32; n++ {
			a = (a + 1) & 0xff
			b = (b + int(state[a])) & 0xff
			state[a], state[b] = state[b], state[a]
			if pad[n]^state[(int(state[a])+int(state[b]))&0xff] != u[n] {
				match = false
				break
			}
		}
		if match {
			return []byte{key[0], key[1], key[2], key[3], key[4]}, true, nil
		}
	}
	return nil, false, nil
}

// rc4KeyAttackGeneral handles R3/R4 (40-bit) via the full computeU verifier
// (MD5(pad||ID) then 20 RC4 rounds). These documents are rare, so correctness
// beats the micro-optimisation of the R2 path.
func (h *Handler) rc4KeyAttackGeneral(ctx context.Context, start, end uint64) ([]byte, bool, error) {
	key := make([]byte, 5)
	for i := start; i < end; i++ {
		if i&0xFFFFF == 0 && ctx != nil {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			default:
			}
		}
		key[0], key[1], key[2], key[3], key[4] = byte(i), byte(i>>8), byte(i>>16), byte(i>>24), byte(i>>32)
		if h.VerifyFileKey(key) {
			return append([]byte(nil), key...), true, nil
		}
	}
	return nil, false, nil
}

// RC4KeyAttackParallel runs RC4KeyAttack over [start, start+count) across
// `workers` goroutines (0 => GOMAXPROCS), stopping as soon as one finds the
// file key. It is the practical CPU driver for the 2^40 sweep; the single-range
// RC4KeyAttack remains the unit for distributed/accelerated sharding. The
// Handler is read-only here, so the goroutines share it safely.
func (h *Handler) RC4KeyAttackParallel(ctx context.Context, start, count uint64, workers int) (key []byte, found bool, err error) {
	if !h.RC4KeyAttackable() {
		return nil, false, nil
	}
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}
	end := start + count
	if end < start || end > MaxRC4FileKey {
		end = MaxRC4FileKey
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
			k, ok, e := h.RC4KeyAttack(ctx, ws, wc)
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
					result = k
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
