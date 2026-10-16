package zipcrypto

// Biham–Kocher known-plaintext key recovery for traditional PKWARE ("ZipCrypto")
// encryption.
//
// ZipCrypto is a cryptographically broken stream cipher: its 96-bit internal
// state can be recovered from a modest run of known plaintext, with no knowledge
// of the password. Recovering the running key state (not the password) is
// legitimate cryptanalysis of a weak-by-design cipher, which is exactly what
// Xcrack is for — we do not weaken any sound cipher here.
//
// Everything in this file is derived directly from the cipher's own key schedule
// (see zipcrypto.go) and cross-validated: the tables are verified to be exact
// inverses of the forward primitives, and the recovery is validated by a round
// trip (encrypt known plaintext, recover the state, decrypt the remainder). No
// third-party code is used.
//
// Scope / status. This file ships the VERIFIED back half of the attack:
//
//   - RecoverInternalState: given the key2 (C) sequence over the known window
//     plus the known plaintext, it reconstructs the full 96-bit internal state
//     and hence decrypts the entire entry. This is exact and fast (seconds).
//   - RollBack: rolls a recovered mid-stream state back across the encryption
//     header (or any preceding ciphertext), recovering those plaintext bytes and
//     the entry's start state so the whole entry decrypts.
//
// The FRONT half — reducing the key2 sequence from the keystream alone (the
// "Zreduction" of Biham–Kocher / kimci86's bkcrack) — is intentionally NOT
// shipped here: a naive enumeration is astronomically over-generating, and an
// efficient, CORRECT reduction plus the fiber-table-based key1/key0 search is a
// substantial, separately-verifiable effort. Until it lands, the key2 sequence
// is expected to come from an external reducer (e.g. a GPU/bkcrack worker reached
// through the challenge-export bridge). See docs/roadmap-enhancements.md.
//
// Notation (per encrypted byte i, state BEFORE encrypting byte i):
//
//	A_i = key0, B_i = key1, C_i = key2   (the three 32-bit words)
//	keystream byte K_i depends only on the low 16 bits of C_i
//	A_{i+1} = crc32(A_i, p_i)                       p_i = plaintext byte i
//	B_{i+1} = (B_i + lsb(A_{i+1})) * MULT + 1
//	C_{i+1} = crc32(C_i, msb(B_{i+1}))

const (
	multConst    = 0x08088405 // key1 multiplier (== 134775813, the value used in update)
	multInvConst = 0xd94fa8cd // modular inverse of multConst mod 2^32 (verified in tests)
)

// MinKnownPlaintext is the smallest run of contiguous known plaintext for which
// recovery is reliable. More is better (it prunes faster and disambiguates).
const MinKnownPlaintext = 12

// crcInvTab inverts one crc32 byte-mix step: crcInvTab[msb(crcTab[b])] = crcTab[b]<<8 ^ b.
var crcInvTab [256]uint32

// ksLow16[k] lists every 16-bit low value of key2 that produces keystream byte k.
var ksLow16 [256][]uint16

func init() {
	for b := 0; b < 256; b++ {
		c := crcTab[b]
		crcInvTab[c>>24] = (c << 8) ^ uint32(b)
	}
	for z := 0; z < (1 << 16); z++ {
		temp := (uint32(z) | 2) & 0xffff
		k := byte((temp * (temp ^ 1)) >> 8)
		ksLow16[k] = append(ksLow16[k], uint16(z))
	}
}

// crc32inv returns the state before a crc32 step that mixed in byte b.
// crc32(crc32inv(x, b), b) == x for all x, b.
func crc32inv(crc uint32, b byte) uint32 {
	return (crc << 8) ^ crcInvTab[crc>>24] ^ uint32(b)
}

func lsb(x uint32) byte { return byte(x) }
func msb(x uint32) byte { return byte(x >> 24) }

// RecoverInternalState reconstructs the full ZipCrypto internal state from the
// key2 (C) sequence over a known-plaintext window and the known plaintext itself.
// key2Seq[i] is the key2 value that produced keystream byte i (i.e. the state
// just before plaintext byte i was encrypted); plain is the corresponding known
// plaintext. They must be equal length and at least MinKnownPlaintext bytes.
//
// On success it returns the complete Keys as they stand just before plain[0] was
// encrypted, and ok=true. From there the caller rolls backward over any preceding
// ciphertext (RollBack) to reach the entry's start and decrypt everything.
//
// Obtaining key2Seq from the keystream alone is the "Zreduction" front half of
// the attack and is not implemented here (see the file comment); supply it from
// an external reducer. The keystream is a function of key2Seq, so this routine
// needs no ciphertext.
func RecoverInternalState(key2Seq []uint32, plain []byte) (Keys, bool) {
	if len(key2Seq) != len(plain) || len(plain) < MinKnownPlaintext {
		return Keys{}, false
	}
	ks := make([]byte, len(key2Seq))
	for i, c := range key2Seq {
		ks[i] = keystreamOf(c)
	}
	return recoverFromKey2(key2Seq, plain, ks)
}

// recoverFromKey2 recovers key1 (B) and key0 (A) from a key2 sequence and the
// known plaintext, then verifies the full state by re-encrypting the window. On
// success it returns the Keys state before plain[0].
func recoverFromKey2(cseq []uint32, plain, ks []byte) (Keys, bool) {
	n := len(cseq)
	if n < 6 {
		return Keys{}, false
	}
	// Top byte of B_i for i in [1,n): msb(B_i) = lsb(C_{i-1} ^ crcInvTab[msb(C_i)]).
	msbB := make([]byte, n)
	for i := 1; i < n; i++ {
		msbB[i] = lsb(cseq[i-1] ^ crcInvTab[cseq[i]>>24])
	}

	bSeq := make([]uint32, n)
	lsbA := make([]byte, n)
	var result Keys
	var found bool

	// Roll the key1 chain backward from a full B[n-1]. The msb(B) filter does not
	// uniquely pin lsb(A_i), so every matching low-A byte is explored (a DFS). The
	// chain terminates at B[1] (B[0]'s top byte is unknown); key0 reconstruction
	// and the full re-encryption then disambiguate.
	var dfs func(i int)
	dfs = func(i int) {
		if found {
			return
		}
		if i == 1 {
			if keys, ok := reconstructKey0(cseq, bSeq, lsbA, plain, ks); ok {
				result, found = keys, true
			}
			return
		}
		// B_i = (B_{i-1} + lsb(A_i)) * MULT + 1  =>  (B_i-1)*MULTINV = B_{i-1} + lsb(A_i)
		tmp := (bSeq[i] - 1) * multInvConst
		want := uint32(msbB[i-1]) << 24
		forEachLowA(tmp, want, func(a byte) {
			bSeq[i-1] = tmp - uint32(a)
			lsbA[i] = a
			dfs(i - 1)
		})
	}

	lastMSB := uint32(msbB[n-1]) << 24
	for low24 := uint32(0); low24 < (1<<24) && !found; low24++ {
		bSeq[n-1] = lastMSB | low24
		dfs(n - 1)
	}
	return result, found
}

// forEachLowA calls cb(a) for every byte a in [0,256) such that the top byte of
// (tmp - a) equals the top byte of want. It computes the matching range directly
// (no 256-wide scan) so the outer 2^24 enumeration stays cheap.
func forEachLowA(tmp, want uint32, cb func(byte)) {
	band := tmp >> 24
	low := tmp & 0xffffff
	w := want >> 24
	switch w {
	case band:
		// a that keeps the top byte: [0, min(255, low)].
		hi := low
		if hi > 255 {
			hi = 255
		}
		for a := uint32(0); a <= hi; a++ {
			cb(byte(a))
		}
	case (band - 1) & 0xff:
		// a that borrows into the next-lower top byte: [low+1, 255] (only if low<255).
		for a := low + 1; a <= 255; a++ {
			cb(byte(a))
		}
	}
}

// reconstructKey0 rebuilds a full key0 from four consecutive recovered low bytes
// of A (positions 2..5, set by the key1 DFS) plus the known plaintext, assembles
// the complete state at position 2, rolls it back to position 0, and verifies by
// re-encrypting the whole window against the keystream.
func reconstructKey0(cseq, bSeq []uint32, lsbA, plain, ks []byte) (Keys, bool) {
	n := len(cseq)
	if n < 6 {
		return Keys{}, false
	}
	// Using A_{i+1} = crcTab[k_i] ^ (A_i>>8), k_i = lsb(A_i)^p_i:
	//   byte1(A_i) = lsb(A_{i+1})   ^ byte0(crcTab[k_i])
	//   byte2(A_i) = byte1(A_{i+1}) ^ byte1(crcTab[k_i])
	//   byte3(A_i) = byte2(A_{i+1}) ^ byte2(crcTab[k_i])
	// and byte1(A_{i+1}) itself expands via the same relation at i+1, etc.
	byte1 := func(i int) byte { return lsbA[i+1] ^ byte(crcTab[lsbA[i]^plain[i]]) }
	byte2 := func(i int) byte { return byte1(i+1) ^ byte(crcTab[lsbA[i]^plain[i]]>>8) }
	byte3 := func(i int) byte { return byte2(i+1) ^ byte(crcTab[lsbA[i]^plain[i]]>>16) }
	// Reconstruct full A[2] (needs lsbA[2..5] and plain[2..4]).
	a2 := uint32(lsbA[2]) | uint32(byte1(2))<<8 | uint32(byte2(2))<<16 | uint32(byte3(2))<<24

	// Full state at position 2, rolled back to position 0.
	state := Keys{k0: a2, k1: bSeq[2], k2: cseq[2]}
	state = invStep(state, plain[1])
	state = invStep(state, plain[0])

	// Verify by re-encrypting the whole known window.
	chk := state
	for i := 0; i < n; i++ {
		if chk.streamByte() != ks[i] {
			return Keys{}, false
		}
		chk.update(plain[i])
	}
	return state, true
}

// invStep inverts one forward key update, given the plaintext byte p that was
// mixed in. It returns the state as it was before that byte was encrypted.
func invStep(k Keys, p byte) Keys {
	c0 := crc32inv(k.k2, msb(k.k1))
	b0 := (k.k1-1)*multInvConst - uint32(lsb(k.k0))
	a0 := crc32inv(k.k0, p)
	return Keys{k0: a0, k1: b0, k2: c0}
}

// RollBack rolls a key state backward over cipher bytes that precede the state's
// current position, recovering those plaintext bytes and the earlier state. It is
// used to walk from a recovered mid-stream state to the start of the entry so the
// whole entry can be decrypted. cipherBefore are the ciphertext bytes immediately
// before the current position, in stream order; the returned plaintext is in the
// same order, and the returned Keys is the state before the first of them.
func (k Keys) RollBack(cipherBefore []byte) (Keys, []byte) {
	plain := make([]byte, len(cipherBefore))
	cur := k
	for i := len(cipherBefore) - 1; i >= 0; i-- {
		// Invert one forward step. Current state = state AFTER encrypting byte i.
		// A_{i+1}=crc32(A_i,p_i); B_{i+1}=(B_i+lsb(A_{i+1}))*MULT+1; C_{i+1}=crc32(C_i,msb(B_{i+1})).
		C0 := crc32inv(cur.k2, msb(cur.k1))
		B0 := (cur.k1-1)*multInvConst - uint32(lsb(cur.k0))
		p := cipherBefore[i] ^ keystreamOf(C0)
		A0 := crc32inv(cur.k0, p)
		plain[i] = p
		cur = Keys{k0: A0, k1: B0, k2: C0}
	}
	return cur, plain
}

// keystreamOf returns the keystream byte for a given key2 value.
func keystreamOf(key2 uint32) byte {
	temp := (key2 | 2) & 0xffff
	return byte((temp * (temp ^ 1)) >> 8)
}
