package pdf

import (
	"bytes"
	"context"
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/rom/xcrypto/prim"
)

// TestReadTableRejectsHugeCountWithoutOOM guards against a crafted sub-table
// count: a header claiming ~4.3e9 chains followed by a truncated stream must
// fail fast with ErrBadTable, not pre-allocate tens of GB and OOM. The fix caps
// the up-front allocation and grows as bytes are actually read.
func TestReadTableRejectsHugeCountWithoutOOM(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("XTHUNDR1")                                  // magic + version
	b.WriteByte(40)                                            // bits
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))       // chainLen
	_ = binary.Write(&b, binary.LittleEndian, uint32(1))       // nsub
	_ = binary.Write(&b, binary.LittleEndian, uint64(0))       // sub seed
	_ = binary.Write(&b, binary.LittleEndian, uint32(1<<32-1)) // lying chain count
	// No chain bytes follow: the first chain read must hit EOF.
	if _, err := ReadTable(&b); err != ErrBadTable {
		t.Fatalf("ReadTable = %v, want ErrBadTable", err)
	}
}

// r2U builds the R2 user-verifier /U = RC4(key5, pad) for a 40-bit key index —
// the exact value a V1/R2 PDF stores, and the thunder table's lookup input.
func r2U(t *testing.T, idx uint64) []byte {
	t.Helper()
	u, err := prim.RC4(keyBytes(idx), pad)
	if err != nil {
		t.Fatalf("RC4: %v", err)
	}
	return u
}

// TestThunderTableRecovers generates a table over a small key space and checks
// that it recovers a large fraction of random keys, that every recovered key is
// exactly correct (reproduces /U, passes VerifyFileKey, and matches the live
// RC4KeyAttack sweep), and that there are no false positives.
func TestThunderTableRecovers(t *testing.T) {
	const bits = 16 // N = 65536 — small enough for a fast, deterministic test
	n := uint64(1) << bits
	tbl, err := GenerateTable(context.Background(), TableParams{
		KeyspaceBits: bits, ChainLen: 256, Chains: 1024, Tables: 4, Workers: 4,
	})
	if err != nil {
		t.Fatalf("GenerateTable: %v", err)
	}
	if tbl.KeyspaceBits() != bits || tbl.ChainLen() != 256 {
		t.Fatalf("header mismatch: bits=%d chainLen=%d", tbl.KeyspaceBits(), tbl.ChainLen())
	}

	rng := rand.New(rand.NewSource(1))
	const trials = 128
	hits := 0
	for i := 0; i < trials; i++ {
		idx := uint64(rng.Intn(int(n)))
		want := keyBytes(idx)
		u := r2U(t, idx)
		got, found := tbl.Lookup(u)
		if !found {
			continue // a coverage miss is allowed; the live sweep would catch it
		}
		hits++
		// Every hit must be exactly correct — false alarms are rejected, not returned.
		if !bytes.Equal(got, want) {
			t.Fatalf("idx %#x: table returned wrong key %x, want %x", idx, got, want)
		}
		h := &Handler{R: 2, Length: 5, Cipher: CipherRC4, U: u}
		if !h.VerifyFileKey(got) {
			t.Fatalf("idx %#x: VerifyFileKey rejected the table's key %x", idx, got)
		}
		cpu, cfound, err := h.RC4KeyAttack(context.Background(), idx, 1)
		if err != nil || !cfound || !bytes.Equal(cpu, got) {
			t.Fatalf("idx %#x: live sweep disagrees: (%x,%v,%v)", idx, cpu, cfound, err)
		}
	}
	if rate := float64(hits) / trials; rate < 0.90 {
		t.Fatalf("coverage too low: %d/%d (%.0f%%); want >= 90%%", hits, trials, rate*100)
	}
	t.Logf("recovered %d/%d keys (%.0f%%), %d chains stored", hits, trials, 100*float64(hits)/trials, tbl.Chains())
}

// TestThunderTableRoundTrip checks the binary serialisation preserves the table:
// a key recovered before WriteTo is still recovered after ReadTable.
func TestThunderTableRoundTrip(t *testing.T) {
	const bits = 14
	tbl, err := GenerateTable(context.Background(), TableParams{
		KeyspaceBits: bits, ChainLen: 128, Chains: 512, Tables: 3,
	})
	if err != nil {
		t.Fatalf("GenerateTable: %v", err)
	}
	// Find a key the table covers, so the assertion is deterministic.
	var u []byte
	var want []byte
	for idx := uint64(0); idx < (1 << bits); idx++ {
		cu := r2U(t, idx)
		if _, ok := tbl.Lookup(cu); ok {
			u, want = cu, keyBytes(idx)
			break
		}
	}
	if u == nil {
		t.Fatal("table covered no key — parameters too small")
	}

	var buf bytes.Buffer
	if _, err := tbl.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	loaded, err := ReadTable(&buf)
	if err != nil {
		t.Fatalf("ReadTable: %v", err)
	}
	if loaded.KeyspaceBits() != tbl.KeyspaceBits() || loaded.ChainLen() != tbl.ChainLen() || loaded.Chains() != tbl.Chains() {
		t.Fatalf("round-trip header/size mismatch")
	}
	got, found := loaded.Lookup(u)
	if !found || !bytes.Equal(got, want) {
		t.Fatalf("after round-trip: got (%x,%v), want %x", got, found, want)
	}
}

// TestThunderTableNoFalsePositive feeds a /U that is not an R2 image of any key
// in the covered space (a random 32-byte value) and confirms the table never
// returns a bogus key — any endpoint match is rejected by the real-/U re-check.
func TestThunderTableNoFalsePositive(t *testing.T) {
	tbl, err := GenerateTable(context.Background(), TableParams{
		KeyspaceBits: 14, ChainLen: 128, Chains: 512, Tables: 2,
	})
	if err != nil {
		t.Fatalf("GenerateTable: %v", err)
	}
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 64; i++ {
		var u [32]byte
		rng.Read(u[:])
		if got, found := tbl.Lookup(u[:]); found {
			// Allowed only if it genuinely reproduces /U (an astronomically unlikely
			// random hit) — never a wrong key.
			if !r2VerifyFull(got, u[:]) {
				t.Fatalf("false positive: returned %x for random /U", got)
			}
		}
	}
}

// TestReadTableRejectsGarbage checks the loader rejects a non-table stream.
func TestReadTableRejectsGarbage(t *testing.T) {
	if _, err := ReadTable(bytes.NewReader([]byte("not a thunder table at all"))); err != ErrBadTable {
		t.Fatalf("ReadTable(garbage) err = %v, want ErrBadTable", err)
	}
	if _, err := ReadTable(bytes.NewReader(nil)); err != ErrBadTable {
		t.Fatalf("ReadTable(empty) err = %v, want ErrBadTable", err)
	}
}
