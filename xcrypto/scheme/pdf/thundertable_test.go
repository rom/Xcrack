package pdf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
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

// TestGenerateTableProgress checks the Progress callback is invoked and reaches
// the full planned chain count by the end of generation.
func TestGenerateTableProgress(t *testing.T) {
	var calls int
	var maxDone, gotTotal uint64
	_, err := GenerateTable(context.Background(), TableParams{
		KeyspaceBits: 12, ChainLen: 16, Chains: 256, Tables: 2,
		Progress: func(done, total uint64) {
			calls++
			if done > maxDone {
				maxDone = done
			}
			gotTotal = total
		},
	})
	if err != nil {
		t.Fatalf("GenerateTable: %v", err)
	}
	if calls == 0 {
		t.Fatal("Progress was never called")
	}
	const want = uint64(2 * 256) // Tables * Chains
	if gotTotal != want {
		t.Fatalf("Progress total = %d, want %d", gotTotal, want)
	}
	if maxDone != want {
		t.Fatalf("final Progress done = %d, want %d (all chains)", maxDone, want)
	}
}

// TestGenerateTableChunkedChainComputer exercises the offloaded (GPU) chain
// path: a supplied ChainComputer is swept in gpuChainChunk-sized pieces, and an
// error partway through a sub-table falls back to the CPU walk without
// double-counting progress (final done must equal total, never exceed it).
func TestGenerateTableChunkedChainComputer(t *testing.T) {
	// GPUChainBatch=4 forces a 16-chain sub-table into several offload calls.
	// Success path: the ChainComputer is called in 4-chain chunks.
	var calls int
	cc := func(n uint64, chainLen int, seed, startIdx, count uint64) ([]uint64, error) {
		calls++
		out := make([]uint64, count)
		for i := range out {
			out[i] = (startIdx + uint64(i)) & (n - 1) // arbitrary but deterministic
		}
		return out, nil
	}
	if _, err := GenerateTable(context.Background(), TableParams{
		KeyspaceBits: 8, ChainLen: 4, Chains: 16, Tables: 1, Chain: cc, GPUChainBatch: 4,
	}); err != nil {
		t.Fatalf("GenerateTable (chunked offload): %v", err)
	}
	if calls < 4 { // 16 chains / batch 4 => 4 calls for the single sub-table
		t.Fatalf("ChainComputer called %d time(s), want >= 4 (not chunked)", calls)
	}

	// Fallback path: the ChainComputer errors after the first chunk. Generation
	// must complete on the CPU and the final progress count must be exactly the
	// planned total — i.e. the partial offload count was rolled back.
	var fcalls int
	ferr := func(n uint64, chainLen int, seed, startIdx, count uint64) ([]uint64, error) {
		if fcalls++; fcalls >= 2 {
			return nil, errors.New("simulated device-lost")
		}
		return make([]uint64, count), nil
	}
	var gotTotal, maxDone uint64
	if _, err := GenerateTable(context.Background(), TableParams{
		KeyspaceBits: 8, ChainLen: 4, Chains: 16, Tables: 1, Chain: ferr, GPUChainBatch: 4,
		Progress: func(done, total uint64) {
			gotTotal = total
			if done > maxDone {
				maxDone = done
			}
		},
	}); err != nil {
		t.Fatalf("GenerateTable (offload fallback): %v", err)
	}
	if gotTotal != 16 {
		t.Fatalf("Progress total = %d, want 16", gotTotal)
	}
	if maxDone != gotTotal {
		t.Fatalf("final done = %d, want %d (partial offload count not rolled back)", maxDone, gotTotal)
	}
}

// TestGPUBatchSize checks the auto batch shrinks as ChainLen grows and that an
// explicit override wins.
func TestGPUBatchSize(t *testing.T) {
	if got := gpuBatchSize(4096, 0); got != gpuChainOpBudget/4096 {
		t.Fatalf("auto batch for chainLen 4096 = %d, want %d", got, gpuChainOpBudget/4096)
	}
	if got := gpuBatchSize(1<<30, 0); got != 1 {
		t.Fatalf("auto batch for a huge chainLen = %d, want 1 (floor)", got)
	}
	if got := gpuBatchSize(256, 99); got != 99 {
		t.Fatalf("override batch = %d, want 99", got)
	}
}

// TestGenerateTableResumeRoundTrip checks that writing to ResumeFile produces a
// file byte-identical to WriteTo of the same table (the checkpoint format is the
// final format) and that it loads back as a complete table.
func TestGenerateTableResumeRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.thunder")
	p := TableParams{KeyspaceBits: 12, ChainLen: 16, Chains: 256, Tables: 4, ResumeFile: path}
	tb, err := GenerateTable(context.Background(), p)
	if err != nil {
		t.Fatalf("GenerateTable: %v", err)
	}
	var buf bytes.Buffer
	if _, err := tb.WriteTo(&buf); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("ResumeFile bytes (%d) != WriteTo bytes (%d)", len(got), buf.Len())
	}
	back, err := ReadTable(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("ReadTable of ResumeFile: %v", err)
	}
	if back.Chains() != tb.Chains() || back.KeyspaceBits() != 12 || back.ChainLen() != 16 {
		t.Fatalf("round-trip mismatch: chains %d/%d bits %d len %d", back.Chains(), tb.Chains(), back.KeyspaceBits(), back.ChainLen())
	}
}

// TestGenerateTableResumeContinues simulates a crash mid-generation (header + 2
// complete sub-tables + a truncated 3rd) and checks the next run loads the 2,
// continues, and reproduces the full table.
func TestGenerateTableResumeContinues(t *testing.T) {
	p := TableParams{KeyspaceBits: 12, ChainLen: 16, Chains: 256, Tables: 4}
	ref, err := GenerateTable(context.Background(), p) // deterministic reference
	if err != nil {
		t.Fatal(err)
	}
	var refBuf bytes.Buffer
	if _, err := ref.WriteTo(&refBuf); err != nil {
		t.Fatal(err)
	}
	full := refBuf.Bytes()

	// Byte offset just past the first two complete sub-table records.
	off := int64(thunderHeaderLen)
	for i := 0; i < 2; i++ {
		off += int64(12 + 10*len(ref.subs[i].ends))
	}
	path := filepath.Join(t.TempDir(), "t.thunder")
	if err := os.WriteFile(path, full[:off+5], 0o600); err != nil { // +5 = a truncated 3rd record
		t.Fatal(err)
	}

	var done, total int
	rp := p
	rp.ResumeFile = path
	rp.OnResume = func(d, tot int) { done, total = d, tot }
	if _, err := GenerateTable(context.Background(), rp); err != nil {
		t.Fatalf("resume GenerateTable: %v", err)
	}
	if done != 2 || total != 4 {
		t.Fatalf("OnResume = (%d,%d), want (2,4)", done, total)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, full) {
		t.Fatalf("resumed file (%d bytes) != full table (%d bytes)", len(got), len(full))
	}
}

// TestGenerateTableResumeParamMismatch checks resuming into a file built with
// different parameters is refused rather than silently corrupting it.
func TestGenerateTableResumeParamMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.thunder")
	p := TableParams{KeyspaceBits: 12, ChainLen: 16, Chains: 256, Tables: 2, ResumeFile: path}
	if _, err := GenerateTable(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	p2 := p
	p2.Tables = 4 // header says 2 sub-tables; must refuse
	if _, err := GenerateTable(context.Background(), p2); err == nil {
		t.Fatal("expected a parameter-mismatch error resuming with different --tables")
	}
}

// TestGenerateTableResumeAlreadyComplete checks that re-running on a finished
// file does nothing and leaves it unchanged.
func TestGenerateTableResumeAlreadyComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.thunder")
	p := TableParams{KeyspaceBits: 12, ChainLen: 16, Chains: 256, Tables: 3, ResumeFile: path}
	if _, err := GenerateTable(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	var done, total int
	p2 := p
	p2.OnResume = func(d, tot int) { done, total = d, tot }
	if _, err := GenerateTable(context.Background(), p2); err != nil {
		t.Fatal(err)
	}
	if done != 3 || total != 3 {
		t.Fatalf("OnResume = (%d,%d), want (3,3) for an already-complete file", done, total)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("already-complete resume rewrote the file")
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
