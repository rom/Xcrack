package pdf

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rom/xcrypto/prim"
)

// Precomputed time-memory trade-off ("Thunder Tables") for the PDF V1/R2 40-bit
// RC4 file key.
//
// The R2 user-verifier is U = RC4(fileKey, pad) where `pad` is the fixed 32-byte
// PDF padding string — a universal constant. So /U is a pure function of the
// 5-byte (40-bit) file key, with NO per-file salt or ID. That makes it the ideal
// rainbow-table target: ONE precomputed table inverts /U → fileKey for EVERY
// V1/R2 document, turning the 2^40 live sweep (RC4KeyAttack) into a seconds-long
// lookup. The one-time cost is the table generation (≈ the full sweep, but paid
// once) plus the storage for the chain endpoints.
//
// This is the classic rainbow trade-off (Oechslin 2003): each chain walks
// key → R2-image → reduced-key for `ChainLen` columns with a column-indexed
// reduction, and only the (start, end) pair is stored. Lookup walks the target
// image toward the endpoint at each hypothesised column, matches an endpoint,
// regenerates the chain to that column, and recovers the key. Every candidate is
// re-checked against the real /U (and the caller re-checks with VerifyFileKey),
// so a table hit is never trusted blindly and a false alarm is simply rejected.
//
// It does NOT apply to R3/R4 (whose /U additionally hashes the per-file /ID) nor
// to the Office 97/2000 RC4 attack (per-file salt): those stay on the live sweep
// (plus the GPU key-search kernels). See RC4KeyAttackable / computeU.

// ErrBadTable reports a malformed or incompatible thunder-table stream.
var ErrBadTable = errors.New("pdf: malformed thunder table")

const (
	thunderMagic      = "XTHUNDR1"         // 8 bytes: format magic + version 1
	thunderMaxBits    = 40                 // the file-key space is 2^40
	thunderSeedStride = 0x9E3779B97F4A7C15 // golden-ratio stride for per-sub-table seeds
)

// TableParams configures thunder-table generation.
type TableParams struct {
	// KeyspaceBits bounds the covered key space to [0, 2^KeyspaceBits). Use 40
	// for a production table that inverts every V1/R2 PDF; a smaller value builds
	// a quick partial table (tests, demos). Clamped to 1..40.
	KeyspaceBits int
	// ChainLen is the number of columns per chain (t). Lookup cost is ~O(t^2) per
	// sub-table, storage shrinks with larger t; coverage needs Chains*ChainLen on
	// the order of the key space.
	ChainLen int
	// Chains is the number of chains per sub-table (m).
	Chains int
	// Tables is the number of independent sub-tables (distinct reductions). More
	// sub-tables raise coverage toward ~100% at a linear storage/lookup cost.
	Tables int
	// Workers is the CPU generation parallelism (0 => GOMAXPROCS).
	Workers int
	// Chain, when non-nil, sources chain endpoints from an external computer (a
	// GPU offload) instead of the CPU walk. It must be byte-identical to the CPU
	// chain — the same R2 image and the same reduction — or lookups will miss.
	// GenerateTable falls back to the CPU walk if it returns an error or a
	// short/empty result, so correctness never depends on the offload.
	Chain ChainComputer
	// GPUChainBatch caps how many chains are sent to Chain per offload call
	// (0 => auto). A single GPU submission must finish well under the device's
	// compute watchdog; a too-large dispatch trips a ring timeout and the driver
	// resets the queue (observed on integrated GPUs). Work per chain is ~ChainLen
	// image ops, so the auto default sizes the batch from ChainLen; lower it if a
	// device still times out. Ignored when Chain is nil.
	GPUChainBatch int
	// Progress, when non-nil, is called periodically during generation with the
	// number of chains completed and the total planned, so a caller can report
	// progress and an ETA. It is invoked from a single background goroutine
	// (never concurrently) at roughly twice a second, plus once when generation
	// finishes; the caller decides how often to actually surface an update. It
	// must be cheap and must not block.
	Progress func(done, total uint64)
	// ResumeFile, when non-empty, makes GenerateTable write each completed
	// sub-table to this file as it finishes (flushed to disk), and — if the file
	// already holds sub-tables built with the same (KeyspaceBits, ChainLen,
	// Tables) — continue after them rather than starting over. So an interrupted
	// or crashed run resumes instead of restarting. A truncated trailing record
	// from a mid-write crash is discarded. Once every sub-table is written the
	// file is exactly what WriteTo produces (a complete, usable table), so no
	// separate finalize step is needed. A file whose header does not match the
	// requested parameters is an error, never a silent overwrite. Empty = the old
	// in-memory behaviour (the caller writes the returned Table itself).
	ResumeFile string
	// OnResume, when set and ResumeFile already contained sub-tables, is called
	// once before generation with how many of Tables were loaded, for a status
	// message. doneSubTables == totalSubTables means the table was already
	// complete and nothing is generated.
	OnResume func(doneSubTables, totalSubTables int)
}

// ChainComputer computes rainbow-chain endpoints for the R2 key space: for each
// start index in [startIdx, startIdx+count) it walks chainLen columns of
// k = reduce(r2Image(k), col, seed, n) and returns the endpoints in order. n is a
// power of two (the key space is 2^bits). It is the seam the GPU thunder-chain
// kernel plugs into; a nil ChainComputer means the pure-Go walk.
type ChainComputer func(n uint64, chainLen int, seed, startIdx, count uint64) (ends []uint64, err error)

// Table is a precomputed rainbow table over the R2 file-key space. It is safe
// for concurrent Lookup once built/loaded.
type Table struct {
	n        uint64 // key space size, 1<<KeyspaceBits
	chainLen int
	subs     []subTable
}

// subTable is one rainbow table: endpoints sorted ascending, starts aligned.
type subTable struct {
	seed   uint64
	starts []uint64 // starts[i] generated end ends[i]
	ends   []uint64 // sorted ascending
}

// KeyspaceBits reports the covered key-space exponent, ChainLen the columns, and
// Chains the total stored chains (summed over sub-tables).
func (t *Table) KeyspaceBits() int { return bitsOf(t.n) }
func (t *Table) ChainLen() int     { return t.chainLen }
func (t *Table) Chains() int {
	n := 0
	for i := range t.subs {
		n += len(t.subs[i].starts)
	}
	return n
}

func bitsOf(n uint64) int {
	b := 0
	for (uint64(1) << b) < n {
		b++
	}
	return b
}

// r2Image returns the first 8 bytes of U = RC4(fileKey, pad) for the 40-bit key
// index, as a little-endian uint64. It is allocation-free (the RC4 state lives on
// the stack), mirroring rc4KeyAttackR2's hot loop, so generation is fast.
func r2Image(idx uint64) uint64 {
	var key [5]byte
	key[0], key[1], key[2], key[3], key[4] = byte(idx), byte(idx>>8), byte(idx>>16), byte(idx>>24), byte(idx>>32)
	var state [256]byte
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
	a, b := 0, 0
	var v uint64
	for n := 0; n < 8; n++ {
		a = (a + 1) & 0xff
		b = (b + int(state[a])) & 0xff
		state[a], state[b] = state[b], state[a]
		ks := state[(int(state[a])+int(state[b]))&0xff]
		v |= uint64(pad[n]^ks) << (8 * uint(n))
	}
	return v
}

// reduce maps an 8-byte image to a key in [0, n) for column col of the sub-table
// with the given seed. Column-indexing (classic rainbow) keeps chains that
// collide in one column from merging wholesale; the seed makes each sub-table an
// independent cover.
func reduce(img uint64, col int, seed, n uint64) uint64 {
	return (img + seed + uint64(col)) % n
}

// keyBytes turns a 40-bit key index into the 5 little-endian key bytes.
func keyBytes(idx uint64) []byte {
	return []byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), byte(idx >> 32)}
}

// GenerateTable builds a thunder table for the given parameters. It parallelises
// chain generation across Workers and is cancellable via ctx.
func GenerateTable(ctx context.Context, p TableParams) (*Table, error) {
	bits := p.KeyspaceBits
	if bits < 1 || bits > thunderMaxBits {
		bits = thunderMaxBits
	}
	if p.ChainLen < 1 || p.Chains < 1 || p.Tables < 1 {
		return nil, errors.New("pdf: thunder table needs ChainLen, Chains and Tables >= 1")
	}
	n := uint64(1) << uint(bits)
	workers := p.Workers
	if workers <= 0 {
		workers = runtime.GOMAXPROCS(0)
	}

	// Progress accounting: a shared chains-done counter the workers advance, read
	// ~twice a second by a background reporter that forwards to p.Progress. The
	// caller throttles the actual output; here we only report the raw counts.
	perSub := uint64(p.Chains)
	if perSub > n {
		perSub = n
	}
	total := uint64(p.Tables) * perSub
	var done atomic.Uint64
	var doneCtr *atomic.Uint64
	if p.Progress != nil {
		doneCtr = &done
		reportCtx, stopReport := context.WithCancel(ctx)
		var reportWG sync.WaitGroup
		reportWG.Add(1)
		go func() {
			defer reportWG.Done()
			tk := time.NewTicker(500 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-reportCtx.Done():
					return
				case <-tk.C:
					p.Progress(done.Load(), total)
				}
			}
		}()
		defer func() {
			stopReport()
			reportWG.Wait()
			p.Progress(done.Load(), total) // final count
		}()
	}

	t := &Table{n: n, chainLen: p.ChainLen, subs: make([]subTable, p.Tables)}

	// Optional incremental output / resume: write each completed sub-table to
	// ResumeFile and continue after any already present from an earlier run.
	start := 0
	var ckpt *os.File
	if p.ResumeFile != "" {
		pre, f, err := openResumeFile(p.ResumeFile, n, p.ChainLen, p.Tables)
		if err != nil {
			return nil, err
		}
		ckpt = f
		defer ckpt.Close()
		start = len(pre)
		copy(t.subs, pre)
		if doneCtr != nil && start > 0 {
			doneCtr.Add(uint64(start) * perSub) // count resumed chains toward progress
		}
		if p.OnResume != nil {
			p.OnResume(start, p.Tables)
		}
	}

	for s := start; s < p.Tables; s++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		seed := uint64(s) * thunderSeedStride // golden-ratio stride per sub-table
		ends, err := generateSub(ctx, n, p.ChainLen, p.Chains, seed, workers, p.Chain, p.GPUChainBatch, doneCtr)
		if err != nil {
			return nil, err
		}
		t.subs[s] = ends
		if ckpt != nil {
			if err := appendSubRecord(ckpt, &ends); err != nil {
				return nil, fmt.Errorf("pdf: thunder checkpoint write: %w", err)
			}
		}
	}
	return t, nil
}

// gpuChainOpBudget bounds the image-op work of one offloaded GPU submission
// (chains-per-call × ChainLen). A single submission must finish well under the
// device's compute watchdog, or the driver resets the queue mid-dispatch (a
// "ring timeout" / "context lost", seen on integrated GPUs); this keeps the auto
// batch small enough regardless of ChainLen. Each submission is a fresh enqueue,
// so overhead (tens of µs) is negligible against a multi-hour table.
const gpuChainOpBudget = 1 << 22 // ~4.2M image ops per submission

// gpuBatchSize is how many chains to offload per Chain call: the caller's
// override when > 0, else gpuChainOpBudget/chainLen (at least 1).
func gpuBatchSize(chainLen, override int) int {
	if override > 0 {
		return override
	}
	n := gpuChainOpBudget / chainLen
	if n < 1 {
		n = 1
	}
	return n
}

// generateSub builds one sub-table. Chain i starts at index i (distinct,
// reproducible starts); endpoints are deduplicated (a merge keeps one chain) and
// sorted so Lookup can binary-search.
func generateSub(ctx context.Context, n uint64, chainLen, chains int, seed uint64, workers int, chain ChainComputer, gpuBatch int, done *atomic.Uint64) (subTable, error) {
	type pair struct{ start, end uint64 }
	starts := chains
	if uint64(starts) > n {
		starts = int(n)
	}
	out := make([]pair, starts)

	// Offloaded (GPU) endpoints, when a byte-identical ChainComputer is supplied.
	// Sweep the sub-table in gpuChainChunk-sized pieces rather than one call, so
	// the shared progress counter advances during the sub-table (not only once at
	// its end) and the per-call host buffer stays bounded. A chunk error or short
	// result falls the whole sub-table back to the CPU walk below; any progress
	// already counted for this sub-table is rolled back first so the CPU recount
	// is not double-counted.
	computed := false
	if chain != nil {
		chunk := gpuBatchSize(chainLen, gpuBatch)
		computed = true
		var counted uint64
		for lo := 0; lo < starts; {
			if err := ctx.Err(); err != nil {
				return subTable{}, err
			}
			hi := lo + chunk
			if hi > starts {
				hi = starts
			}
			ends, err := chain(n, chainLen, seed, uint64(lo), uint64(hi-lo))
			if err != nil || len(ends) != hi-lo {
				computed = false
				break
			}
			for i, e := range ends {
				out[lo+i] = pair{start: uint64(lo + i), end: e}
			}
			if done != nil {
				done.Add(uint64(hi - lo))
				counted += uint64(hi - lo)
			}
			lo = hi
		}
		if !computed && done != nil && counted > 0 {
			done.Add(^(counted - 1)) // two's-complement subtract: undo the partial count
		}
	}

	if !computed {
		var wg sync.WaitGroup
		var cancelled sync.Once
		var cerr error
		// Check ctx roughly every ~2^20 image ops so a Ctrl-C pauses within a
		// fraction of a second regardless of chain length (each chain is chainLen
		// ops, so a fixed per-chain stride would wait chainLen×stride ops — minutes
		// at the large default chainLen).
		checkEvery := (1 << 20) / chainLen
		if checkEvery < 1 {
			checkEvery = 1
		}
		chunk := (starts + workers - 1) / workers
		for w := 0; w < workers; w++ {
			lo := w * chunk
			if lo >= starts {
				break
			}
			hi := lo + chunk
			if hi > starts {
				hi = starts
			}
			wg.Add(1)
			go func(lo, hi int) {
				defer wg.Done()
				// Count chains locally and flush to the shared counter in batches to
				// keep progress accounting off the per-chain hot path.
				const flushEvery = 1024
				local := 0
				flush := func() {
					if done != nil && local > 0 {
						done.Add(uint64(local))
						local = 0
					}
				}
				defer flush()
				for i := lo; i < hi; i++ {
					if i%checkEvery == 0 && ctx.Err() != nil {
						cancelled.Do(func() { cerr = ctx.Err() })
						return
					}
					k := uint64(i)
					for col := 0; col < chainLen; col++ {
						k = reduce(r2Image(k), col, seed, n)
					}
					out[i] = pair{start: uint64(i), end: k}
					if local++; local >= flushEvery {
						flush()
					}
				}
			}(lo, hi)
		}
		wg.Wait()
		if cerr != nil {
			return subTable{}, cerr
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].end < out[b].end })
	// Deduplicate endpoints: chains that merge share an endpoint; keep the first.
	st := subTable{seed: seed, starts: make([]uint64, 0, len(out)), ends: make([]uint64, 0, len(out))}
	for i := range out {
		if i > 0 && out[i].end == out[i-1].end {
			continue
		}
		st.starts = append(st.starts, out[i].start)
		st.ends = append(st.ends, out[i].end)
	}
	return st, nil
}

// Lookup inverts the R2 user-verifier u (the document's /U, at least 32 bytes),
// returning the 5-byte file key on success. It re-checks every candidate against
// the real /U, so a false alarm is rejected and a returned key always reproduces
// /U exactly; found=false means the key was not in the table's coverage (run the
// live sweep). Safe for concurrent use.
func (t *Table) Lookup(u []byte) (key []byte, found bool) {
	if len(u) < 32 || t == nil || t.n == 0 {
		return nil, false
	}
	target := binary.LittleEndian.Uint64(u[:8])
	var full [32]byte
	copy(full[:], u[:32])

	// scanColumn tests the hypothesis "the key sits at column col of this
	// sub-table": walk the target image to the endpoint, and for every chain with
	// that endpoint regenerate from its start and verify against the real /U. It
	// is read-only over immutable table data, so it is safe to call concurrently.
	scanColumn := func(sub *subTable, col int) ([]byte, bool) {
		k := reduce(target, col, sub.seed, t.n)
		for c := col + 1; c < t.chainLen; c++ {
			k = reduce(r2Image(k), c, sub.seed, t.n)
		}
		lo := sort.Search(len(sub.ends), func(i int) bool { return sub.ends[i] >= k })
		for i := lo; i < len(sub.ends) && sub.ends[i] == k; i++ {
			cand := sub.starts[i]
			for c := 0; c < col; c++ {
				cand = reduce(r2Image(cand), c, sub.seed, t.n)
			}
			if r2Image(cand) != target {
				continue // false alarm (chains merged downstream of a different key)
			}
			if kb := keyBytes(cand); r2VerifyFull(kb, full[:]) {
				return kb, true
			}
		}
		return nil, false
	}

	// The dominant cost is Σ_col (chainLen-col) image walks per sub-table. Split
	// the column space across workers so a big table inverts in seconds, not the
	// single-threaded minutes the serial scan would take. R2 has a unique file
	// key (every returned key is verified against /U), so which matching column a
	// worker finds first is irrelevant — the first verified hit wins and cancels
	// the rest.
	workers := runtime.GOMAXPROCS(0)
	if workers > t.chainLen {
		workers = t.chainLen
	}
	if workers <= 1 {
		for s := range t.subs {
			for col := t.chainLen - 1; col >= 0; col-- {
				if kb, ok := scanColumn(&t.subs[s], col); ok {
					return kb, true
				}
			}
		}
		return nil, false
	}

	var (
		wg     sync.WaitGroup
		once   sync.Once
		result []byte
		stop   atomic.Bool
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for col := t.chainLen - 1 - w; col >= 0; col -= workers {
				if stop.Load() {
					return
				}
				for s := range t.subs {
					if kb, ok := scanColumn(&t.subs[s], col); ok {
						once.Do(func() { result = kb })
						stop.Store(true)
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()
	if result != nil {
		return result, true
	}
	return nil, false
}

// r2VerifyFull confirms key reproduces the full 32-byte R2 /U — the authoritative
// check behind the 8-byte image match. R2 /U is exactly RC4(fileKey, pad).
func r2VerifyFull(key5, u32 []byte) bool {
	out, err := prim.RC4(key5, pad)
	if err != nil || len(out) < 32 {
		return false
	}
	return prim.ConstantTimeEqual(out[:32], u32)
}

// --- on-disk format -----------------------------------------------------------
// header: magic(8) | bits(1) | chainLen(4 LE) | nsub(4 LE)
// record: seed(8 LE) | count(4 LE) | count × (start[5] | end[5])
// Each record is independently parseable, so the file can be written — and
// resumed — one sub-table at a time; a complete file is exactly what WriteTo
// emits, readable by ReadTable.

const thunderHeaderLen = 8 + 1 + 4 + 4 // 17

func writeTableHeader(w io.Writer, n uint64, chainLen, nsub int) (int, error) {
	var hdr [thunderHeaderLen]byte
	copy(hdr[:8], thunderMagic)
	hdr[8] = byte(bitsOf(n))
	binary.LittleEndian.PutUint32(hdr[9:], uint32(chainLen))
	binary.LittleEndian.PutUint32(hdr[13:], uint32(nsub))
	return w.Write(hdr[:])
}

// readTableHeader parses the 17-byte header and returns the key space, chain
// length and sub-table count. A bad magic, bits or count yields ErrBadTable.
func readTableHeader(r io.Reader) (n uint64, chainLen, nsub int, err error) {
	var hdr [thunderHeaderLen]byte
	if _, e := io.ReadFull(r, hdr[:]); e != nil {
		return 0, 0, 0, ErrBadTable
	}
	if string(hdr[:8]) != thunderMagic {
		return 0, 0, 0, ErrBadTable
	}
	bits := int(hdr[8])
	if bits < 1 || bits > thunderMaxBits {
		return 0, 0, 0, ErrBadTable
	}
	chainLen = int(binary.LittleEndian.Uint32(hdr[9:]))
	nsub = int(binary.LittleEndian.Uint32(hdr[13:]))
	if chainLen < 1 || nsub < 1 || nsub > 1<<20 {
		return 0, 0, 0, ErrBadTable
	}
	return uint64(1) << uint(bits), chainLen, nsub, nil
}

// writeSubRecord writes one sub-table record and returns the bytes written.
func writeSubRecord(w io.Writer, sub *subTable) (int, error) {
	var pre [12]byte
	binary.LittleEndian.PutUint64(pre[:8], sub.seed)
	binary.LittleEndian.PutUint32(pre[8:], uint32(len(sub.ends)))
	total, err := w.Write(pre[:])
	if err != nil {
		return total, err
	}
	var k5 [5]byte
	for i := range sub.ends {
		putKey5(k5[:], sub.starts[i])
		if nw, err := w.Write(k5[:]); err != nil {
			return total + nw, err
		} else {
			total += nw
		}
		putKey5(k5[:], sub.ends[i])
		if nw, err := w.Write(k5[:]); err != nil {
			return total + nw, err
		} else {
			total += nw
		}
	}
	return total, nil
}

// readSubRecord reads one sub-table record. It returns io.EOF when the reader is
// cleanly at a record boundary (no record present) and io.ErrUnexpectedEOF when a
// record is present but truncated — a resume loader treats both as "stop here",
// keeping only the complete records read so far. The initial slice capacity is
// capped so a corrupt/hostile count cannot force a huge allocation before a short
// read fails.
func readSubRecord(r io.Reader) (subTable, error) {
	var pre [12]byte
	if _, err := io.ReadFull(r, pre[:]); err != nil {
		if err == io.EOF {
			return subTable{}, io.EOF
		}
		return subTable{}, io.ErrUnexpectedEOF
	}
	m := int(binary.LittleEndian.Uint32(pre[8:]))
	capHint := m
	if capHint < 0 || capHint > 1<<16 {
		capHint = 1 << 16
	}
	sub := subTable{
		seed:   binary.LittleEndian.Uint64(pre[:8]),
		starts: make([]uint64, 0, capHint),
		ends:   make([]uint64, 0, capHint),
	}
	var k5 [5]byte
	for i := 0; i < m; i++ {
		if _, err := io.ReadFull(r, k5[:]); err != nil {
			return subTable{}, io.ErrUnexpectedEOF
		}
		start := getKey5(k5[:])
		if _, err := io.ReadFull(r, k5[:]); err != nil {
			return subTable{}, io.ErrUnexpectedEOF
		}
		sub.starts = append(sub.starts, start)
		sub.ends = append(sub.ends, getKey5(k5[:]))
	}
	return sub, nil
}

// WriteTo serialises the table in a compact binary form (keys as 5 bytes).
func (t *Table) WriteTo(w io.Writer) (int64, error) {
	total, err := writeTableHeader(w, t.n, t.chainLen, len(t.subs))
	if err != nil {
		return int64(total), err
	}
	for s := range t.subs {
		nw, err := writeSubRecord(w, &t.subs[s])
		total += nw
		if err != nil {
			return int64(total), err
		}
	}
	return int64(total), nil
}

// ReadTable deserialises a table written by WriteTo. A truncated or malformed
// stream is ErrBadTable.
func ReadTable(r io.Reader) (*Table, error) {
	n, chainLen, nsub, err := readTableHeader(r)
	if err != nil {
		return nil, err
	}
	t := &Table{n: n, chainLen: chainLen, subs: make([]subTable, nsub)}
	for s := 0; s < nsub; s++ {
		sub, err := readSubRecord(r)
		if err != nil {
			return nil, ErrBadTable
		}
		t.subs[s] = sub
	}
	return t, nil
}

// openResumeFile opens (or creates) the incremental output file at path for a
// table with the given parameters. A fresh file gets the header and no
// pre-loaded sub-tables. An existing file has its header validated against
// (n, chainLen, nsub); every complete sub-table record is loaded (a truncated
// trailing record from an interrupted run is discarded), the file is truncated to
// the last complete record and positioned for appending. A non-thunder file or a
// parameter mismatch is an error rather than a silent overwrite.
func openResumeFile(path string, n uint64, chainLen, nsub int) (pre []subTable, f *os.File, err error) {
	f, err = os.OpenFile(path, os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrNotExist) {
		f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, nil, err
		}
		if _, werr := writeTableHeader(f, n, chainLen, nsub); werr != nil {
			f.Close()
			return nil, nil, werr
		}
		return nil, f, nil
	}
	if err != nil {
		return nil, nil, err
	}
	fn, fChainLen, fNsub, herr := readTableHeader(f)
	if herr != nil {
		f.Close()
		return nil, nil, fmt.Errorf("%s is not a thunder table (remove it or choose another output path): %w", path, herr)
	}
	if fn != n || fChainLen != chainLen || fNsub != nsub {
		f.Close()
		return nil, nil, fmt.Errorf("%s was built with different parameters; remove it or match --bits/--length/--tables", path)
	}
	offset := int64(thunderHeaderLen)
	br := bufio.NewReaderSize(f, 1<<20)
	for len(pre) < nsub {
		sub, rerr := readSubRecord(br)
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break // clean boundary, or a truncated trailing record: stop
		}
		if rerr != nil {
			f.Close()
			return nil, nil, rerr
		}
		if sub.seed != uint64(len(pre))*thunderSeedStride {
			f.Close()
			return nil, nil, fmt.Errorf("%s: inconsistent checkpoint at sub-table %d", path, len(pre))
		}
		pre = append(pre, sub)
		offset += int64(12 + 10*len(sub.ends))
	}
	if terr := f.Truncate(offset); terr != nil { // drop any partial tail
		f.Close()
		return nil, nil, terr
	}
	if _, serr := f.Seek(offset, io.SeekStart); serr != nil {
		f.Close()
		return nil, nil, serr
	}
	return pre, f, nil
}

// appendSubRecord writes one completed sub-table to the open output file and
// flushes it to disk, so an interrupted run leaves a valid, resumable prefix.
func appendSubRecord(f *os.File, sub *subTable) error {
	bw := bufio.NewWriterSize(f, 1<<20)
	if _, err := writeSubRecord(bw, sub); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	return f.Sync()
}

// BenchImageRate measures how many R2 image evaluations one core does per second
// over the given window — used to estimate thunder-table generation time. It is a
// quick micro-benchmark, not a precise figure.
func BenchImageRate(d time.Duration) float64 {
	if d <= 0 {
		d = 100 * time.Millisecond
	}
	deadline := time.Now().Add(d)
	var n uint64
	for {
		for i := 0; i < 4096; i++ {
			_ = r2Image(n + uint64(i))
		}
		n += 4096
		if time.Now().After(deadline) {
			break
		}
	}
	return float64(n) / d.Seconds()
}

func putKey5(b []byte, v uint64) {
	b[0], b[1], b[2], b[3], b[4] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24), byte(v>>32)
}

func getKey5(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32
}
