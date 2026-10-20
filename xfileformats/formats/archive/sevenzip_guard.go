package archive

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"math/bits"

	"github.com/bodgit/sevenzip"
)

// 7z header property ids (bodgit/sevenzip types.go, iota from idEnd=0). Only the
// ids the pre-scan actually dispatches on are named; the file-property ids
// (empty-stream/file, times, names, attributes) are deliberately absent because
// every allocation they drive is sized by the already-checked file count.
const (
	szIDEnd = iota
	szIDHeader
	szIDArchiveProperties
	szIDAdditionalStreamsInfo
	szIDMainStreamsInfo
	szIDFilesInfo
	szIDPackInfo
	szIDUnpackInfo
	szIDSubStreamsInfo
	szIDSize
	szIDCRC
	szIDFolder
	szIDCodersUnpackSize
	szIDNumUnpackStream
)

const szIDEncodedHeader = 23 // 0x17

var (
	// errSzOversizeHeader rejects a 7z whose header declares more
	// files/streams/folders/coders than the archive length could ever back.
	errSzOversizeHeader = errors.New("archive: 7z header declares more structure than the file size can hold")
	// errSzBail stops the pre-scan at a structure it does not mirror; the gate
	// then stands aside (fail-open) and lets the library do the real parse, so
	// an incomplete mirror never rejects a valid archive, only fails to add a
	// bound it did not reach.
	errSzBail = errors.New("archive: 7z header pre-scan reached an unmirrored structure")
)

// szNewReader opens a 7z archive after a bounded, size-proportional pre-scan of
// its header (szWithinSize). The bodgit/sevenzip parser sizes several slice
// allocations straight from untrusted header count varints, capping them only
// at MaxUint32 (checkUint64), so a ~40-byte crafted archive can drive a single
// make([]FileHeader, 4.29e9) ≈ 480 GiB. The engine's recover() guard cannot
// catch that: a make that large does not panic (it is well under the runtime's
// maxAlloc), so the runtime instead throws a fatal, unrecoverable "out of
// memory". Pre-rejecting the impossible counts keeps the parser's memory use
// proportional to its input. All callers that open a 7z go through here.
func szNewReader(r io.ReaderAt, size int64, pw string) (*sevenzip.Reader, error) {
	if err := szWithinSize(r, size); err != nil {
		return nil, err
	}
	return sevenzip.NewReaderWithPassword(r, size, pw)
}

// szWithinSize pre-scans a 7z archive's header and returns errSzOversizeHeader
// when it declares more structure than the file could hold. It mirrors the
// library's header grammar (bodgit/sevenzip@v1.6.5) only as far as the
// count-driven allocations on the plaintext (idHeader) path and in the
// StreamsInfo of an encoded header (idEncodedHeader) — the counts the library
// reaches before it has verified anything. Anything it does not recognise (an
// embedded-signature archive, an external-data reference, an unknown property,
// a short read) it stands aside on, letting the library parse unchanged, so the
// gate can only ever reject the provably impossible, never a valid archive.
//
// Residual: an encoded header's *inner* (compressed) metadata is decompressed
// by the library before it is parsed, so its counts are out of reach of a
// size-based outer gate. A decompression-bomb header can therefore still drive
// an oversize allocation. Fully closing that needs an upstream proportionality
// fix in the parser, or running untrusted-archive parsing under an OS memory
// limit in the service tier; see docs/threat-model.md.
func szWithinSize(r io.ReaderAt, size int64) error {
	if size < 32 {
		return nil // too short for the library to parse; it will reject it cleanly
	}
	var sh [32]byte
	if _, err := r.ReadAt(sh[:], 0); err != nil {
		return nil
	}
	if string(sh[:6]) != "7z\xbc\xaf\x27\x1c" {
		return nil // signature not at offset 0; the library's findSignature handles it
	}
	offset := binary.LittleEndian.Uint64(sh[12:20])
	nextSize := binary.LittleEndian.Uint64(sh[20:28])
	if offset > uint64(size) {
		return nil // header claims to start past EOF; the library will fail cleanly
	}
	start := 32 + int64(offset)
	if start >= size {
		return nil
	}
	avail := uint64(size - start)
	readLen := nextSize
	if readLen > avail {
		readLen = avail
	}
	br := bufio.NewReader(io.NewSectionReader(r, start, int64(readLen))) //nolint:gosec
	id, err := br.ReadByte()
	if err != nil {
		return nil
	}
	sc := &szScan{r: br, max: uint64(size)}
	switch id {
	case szIDHeader:
		err = sc.header()
	case szIDEncodedHeader:
		err = sc.streamsInfo()
	default:
		return nil
	}
	if errors.Is(err, errSzOversizeHeader) {
		return err
	}
	return nil // nil, io error, or errSzBail → stand aside, let the library parse
}

// szScan walks a 7z header through a reader bounded to the bytes actually
// present, so even a buggy walk can read no more than the file holds. max is
// the archive size: no structural count may exceed it.
type szScan struct {
	r   *bufio.Reader
	max uint64
}

// uvarint mirrors sevenzip's readUint64 number encoding.
func (s *szScan) uvarint() (uint64, error) {
	b, err := s.r.ReadByte()
	if err != nil {
		return 0, err
	}
	l := bits.LeadingZeros8(^b)
	var v uint64
	if l < 7 {
		v |= uint64(b&((1<<(8-l))-1)) << (8 * l)
	}
	for i := 0; i < l; i++ {
		nb, err := s.r.ReadByte()
		if err != nil {
			return 0, err
		}
		v |= uint64(nb) << (8 * i)
	}
	return v, nil
}

// count reads a length-like varint and rejects it when it exceeds the archive
// size — a value no valid archive can back with real bytes.
func (s *szScan) count() (uint64, error) {
	v, err := s.uvarint()
	if err != nil {
		return 0, err
	}
	if v > s.max {
		return 0, errSzOversizeHeader
	}
	return v, nil
}

func (s *szScan) discardVarints(n uint64) error {
	for i := uint64(0); i < n; i++ {
		if _, err := s.uvarint(); err != nil {
			return err
		}
	}
	return nil
}

func (s *szScan) skip(n uint64) error {
	_, err := io.CopyN(io.Discard, s.r, int64(n)) //nolint:gosec
	return err
}

// crcBytes consumes the (optional-bool + uint32 array) a readCRC(count) would,
// so the walk stays byte-aligned. count has already been checked against max.
func (s *szScan) crcBytes(count uint64) error {
	all, err := s.r.ReadByte()
	if err != nil {
		return err
	}
	defined := count
	if all == 0 {
		defined = 0
		var cur byte
		for i := uint64(0); i < count; i++ {
			if i&7 == 0 {
				if cur, err = s.r.ReadByte(); err != nil {
					return err
				}
			}
			if cur&(0x80>>(i&7)) != 0 {
				defined++
			}
		}
	}
	return s.skip(defined * 4)
}

// header mirrors readHeader on the plaintext path: an optional MainStreamsInfo,
// then FilesInfo whose NumFiles sizes every file-property allocation.
func (s *szScan) header() error {
	id, err := s.r.ReadByte()
	if err != nil {
		return err
	}
	if id == szIDArchiveProperties || id == szIDAdditionalStreamsInfo {
		return errSzBail // library errors here (TODO), before any count-driven make
	}
	if id == szIDMainStreamsInfo {
		if err := s.streamsInfo(); err != nil {
			return err
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	if id == szIDFilesInfo {
		if _, err := s.count(); err != nil { // NumFiles
			return err
		}
	}
	return nil
}

// streamsInfo mirrors readStreamsInfo: optional PackInfo, UnpackInfo, then
// SubStreamsInfo.
func (s *szScan) streamsInfo() error {
	id, err := s.r.ReadByte()
	if err != nil {
		return err
	}
	if id == szIDPackInfo {
		if err := s.packInfo(); err != nil {
			return err
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	var folders uint64
	haveUnpack := false
	if id == szIDUnpackInfo {
		if folders, err = s.unpackInfo(); err != nil {
			return err
		}
		haveUnpack = true
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	if id == szIDSubStreamsInfo {
		if !haveUnpack {
			return errSzBail // library: errMissingUnpackInfo
		}
		if err := s.subStreamsInfo(folders); err != nil {
			return err
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	if id != szIDEnd {
		return errSzBail
	}
	return nil
}

// packInfo mirrors readPackInfo: NumPackStreams sizes a readCRC/readOptionalBool
// allocation.
func (s *szScan) packInfo() error {
	if _, err := s.uvarint(); err != nil { // pack position (not a count)
		return err
	}
	streams, err := s.count()
	if err != nil {
		return err
	}
	id, err := s.r.ReadByte()
	if err != nil {
		return err
	}
	if id == szIDSize {
		if err := s.discardVarints(streams); err != nil {
			return err
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	if id == szIDCRC {
		if err := s.crcBytes(streams); err != nil {
			return err
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	if id != szIDEnd {
		return errSzBail
	}
	return nil
}

// unpackInfo mirrors readUnpackInfo: NumFolders sizes a readCRC allocation and
// each folder's output-stream count sizes an unpack-size list. Returns the
// folder count for SubStreamsInfo.
func (s *szScan) unpackInfo() (uint64, error) {
	id, err := s.r.ReadByte()
	if err != nil {
		return 0, err
	}
	if id != szIDFolder {
		return 0, errSzBail
	}
	folders, err := s.count()
	if err != nil {
		return 0, err
	}
	external, err := s.r.ReadByte()
	if err != nil {
		return 0, err
	}
	if external != 0 {
		return 0, errSzBail // library: TODO external
	}
	outs := make([]uint64, 0, min(folders, 1024))
	for i := uint64(0); i < folders; i++ {
		out, err := s.folder()
		if err != nil {
			return 0, err
		}
		outs = append(outs, out)
	}
	if id, err = s.r.ReadByte(); err != nil {
		return 0, err
	}
	if id != szIDCodersUnpackSize {
		return 0, errSzBail
	}
	for _, out := range outs {
		if err := s.discardVarints(out); err != nil { // one unpack size per output stream
			return 0, err
		}
	}
	if id, err = s.r.ReadByte(); err != nil {
		return 0, err
	}
	if id == szIDCRC {
		if err := s.crcBytes(folders); err != nil {
			return 0, err
		}
		if id, err = s.r.ReadByte(); err != nil {
			return 0, err
		}
	}
	if id != szIDEnd {
		return 0, errSzBail
	}
	return folders, nil
}

// folder mirrors readFolder: the coder count and the per-folder input/output
// stream sums each size an allocation. Returns the folder's output-stream sum.
func (s *szScan) folder() (uint64, error) {
	coders, err := s.count()
	if err != nil {
		return 0, err
	}
	var inSum, outSum uint64
	for i := uint64(0); i < coders; i++ {
		flags, err := s.r.ReadByte()
		if err != nil {
			return 0, err
		}
		if err := s.skip(uint64(flags & 0x0f)); err != nil { // coder id bytes
			return 0, err
		}
		in, out := uint64(1), uint64(1)
		if flags&0x10 != 0 { // complex coder: explicit in/out counts
			if in, err = s.count(); err != nil {
				return 0, err
			}
			if out, err = s.count(); err != nil {
				return 0, err
			}
		}
		if flags&0x20 != 0 { // coder has properties
			propSize, err := s.count()
			if err != nil {
				return 0, err
			}
			if err := s.skip(propSize); err != nil {
				return 0, err
			}
		}
		inSum += in
		outSum += out
		if inSum > s.max || outSum > s.max {
			return 0, errSzOversizeHeader
		}
	}
	if outSum == 0 || inSum < outSum {
		return 0, errSzBail // library: non-zero / bind-pair invariants
	}
	bindPairs := outSum - 1
	if err := s.discardVarints(bindPairs * 2); err != nil { // in/out index per bind pair
		return 0, err
	}
	if packed := inSum - bindPairs; packed != 1 {
		if err := s.discardVarints(packed); err != nil {
			return 0, err
		}
	}
	return outSum, nil
}

// subStreamsInfo mirrors readSubStreamsInfo: the total substream count (summed
// from per-folder counts) sizes two allocations.
func (s *szScan) subStreamsInfo(folders uint64) error {
	id, err := s.r.ReadByte()
	if err != nil {
		return err
	}
	streams := make([]uint64, 0, min(folders, 1024))
	var files uint64
	if id == szIDNumUnpackStream {
		for i := uint64(0); i < folders; i++ {
			n, err := s.uvarint() // readUint64: unbounded in the library
			if err != nil {
				return err
			}
			files += n
			if files > s.max {
				return errSzOversizeHeader
			}
			streams = append(streams, n)
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	} else {
		files = folders
		for i := uint64(0); i < folders; i++ {
			streams = append(streams, 1)
		}
	}
	if files > s.max {
		return errSzOversizeHeader
	}
	if id == szIDSize {
		for _, n := range streams {
			if n == 0 {
				continue
			}
			if err := s.discardVarints(n - 1); err != nil {
				return err
			}
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	if id == szIDCRC {
		if err := s.crcBytes(files); err != nil {
			return err
		}
		if id, err = s.r.ReadByte(); err != nil {
			return err
		}
	}
	if id != szIDEnd {
		return errSzBail
	}
	return nil
}
