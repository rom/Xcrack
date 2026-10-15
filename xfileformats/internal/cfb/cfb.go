// Package cfb is a minimal, bounded reader and writer for the Compound File
// Binary format (a.k.a. OLE2 / CFBF), the container used by encrypted Microsoft
// Office documents. It supports the common v3 layout (512-byte sectors, 64-byte
// mini sectors) and both the FAT and mini-FAT storage paths. It extracts named
// streams; it does not interpret their contents. Parsing is defensive: all
// chains are bounded and malformed input yields an error, never a panic.
package cfb

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// ErrMalformed indicates the input is not a valid CFB file.
var ErrMalformed = errors.New("cfb: malformed compound file")

const (
	sig        = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
	fatSect    = 0xFFFFFFFD
	maxChain   = 1 << 24 // hard cap on chain length (bomb guard)
)

// IsCFB reports whether peek starts with the CFB signature.
func IsCFB(peek []byte) bool { return len(peek) >= 8 && string(peek[:8]) == sig }

// File is a parsed compound file exposing its named streams.
type File struct{ streams map[string][]byte }

// Stream returns the bytes of the named stream.
func (f *File) Stream(name string) ([]byte, bool) { b, ok := f.streams[name]; return b, ok }

// Names returns the stream names present.
func (f *File) Names() []string {
	out := make([]string, 0, len(f.streams))
	for n := range f.streams {
		out = append(out, n)
	}
	return out
}

func u16(b []byte, off int) uint16 { return binary.LittleEndian.Uint16(b[off:]) }
func u32(b []byte, off int) uint32 { return binary.LittleEndian.Uint32(b[off:]) }
func u64(b []byte, off int) uint64 { return binary.LittleEndian.Uint64(b[off:]) }

func decodeName(b []byte, nameLenBytes int) string {
	if nameLenBytes < 2 || nameLenBytes > len(b) {
		return ""
	}
	n := (nameLenBytes - 2) / 2 // drop null terminator
	u := make([]uint16, n)
	for i := 0; i < n; i++ {
		u[i] = u16(b, i*2)
	}
	return string(utf16.Decode(u))
}

// Open parses a compound file from data.
func Open(data []byte) (*File, error) {
	if len(data) < 512 || !IsCFB(data) {
		return nil, ErrMalformed
	}
	sectorSize := 1 << u16(data, 30)
	miniSize := 1 << u16(data, 32)
	if sectorSize != 512 && sectorSize != 4096 {
		return nil, ErrMalformed
	}
	if miniSize <= 0 || miniSize > sectorSize {
		return nil, ErrMalformed
	}
	firstDir := u32(data, 48)
	miniCutoff := u32(data, 56)
	firstMiniFAT := u32(data, 60)
	numMiniFAT := u32(data, 64)
	firstDIFAT := u32(data, 68)
	numDIFAT := u32(data, 72)

	readSector := func(sid uint32) ([]byte, error) {
		off := 512 + int(sid)*sectorSize
		if sid >= 0xFFFFFFFC || off < 0 || off+sectorSize > len(data) {
			return nil, ErrMalformed
		}
		return data[off : off+sectorSize], nil
	}

	// Collect FAT sector ids: header DIFAT (109 entries) + DIFAT sector chain.
	var fatSids []uint32
	for i := 0; i < 109; i++ {
		v := u32(data, 76+i*4)
		if v < 0xFFFFFFFC {
			fatSids = append(fatSids, v)
		}
	}
	for sid, steps := firstDIFAT, 0; sid < 0xFFFFFFFC && numDIFAT > 0 && steps < int(numDIFAT)+1; steps++ {
		sec, err := readSector(sid)
		if err != nil {
			return nil, err
		}
		for i := 0; i < sectorSize/4-1; i++ {
			if v := u32(sec, i*4); v < 0xFFFFFFFC {
				fatSids = append(fatSids, v)
			}
		}
		sid = u32(sec, sectorSize-4)
	}

	// Build the FAT.
	fat := make([]uint32, 0, len(fatSids)*(sectorSize/4))
	for _, fs := range fatSids {
		sec, err := readSector(fs)
		if err != nil {
			return nil, err
		}
		for i := 0; i < sectorSize/4; i++ {
			fat = append(fat, u32(sec, i*4))
		}
	}

	maxSectors := len(data)/sectorSize + 2
	readChain := func(start uint32) ([]byte, error) {
		var out []byte
		for sid, seen := start, 0; sid < 0xFFFFFFFC; seen++ {
			if seen > maxSectors || seen > maxChain {
				return nil, ErrMalformed
			}
			sec, err := readSector(sid)
			if err != nil {
				return nil, err
			}
			out = append(out, sec...)
			if int(sid) >= len(fat) {
				return nil, ErrMalformed
			}
			sid = fat[sid]
		}
		return out, nil
	}

	dirBytes, err := readChain(firstDir)
	if err != nil {
		return nil, err
	}

	var miniFAT []uint32
	if numMiniFAT > 0 && firstMiniFAT < 0xFFFFFFFC {
		mb, err := readChain(firstMiniFAT)
		if err != nil {
			return nil, err
		}
		for i := 0; i+4 <= len(mb); i += 4 {
			miniFAT = append(miniFAT, u32(mb, i))
		}
	}

	type entry struct {
		name  string
		typ   byte
		start uint32
		size  uint64
	}
	var entries []entry
	var rootStart uint32 = endOfChain
	var rootSize uint64
	for off := 0; off+128 <= len(dirBytes); off += 128 {
		e := dirBytes[off : off+128]
		typ := e[66]
		if typ == 0 { // unknown/unallocated
			continue
		}
		en := entry{
			name:  decodeName(e[:64], int(u16(e, 64))),
			typ:   typ,
			start: u32(e, 116),
			size:  u64(e, 120),
		}
		if typ == 5 { // root
			rootStart, rootSize = en.start, en.size
		}
		entries = append(entries, en)
	}

	var miniStream []byte
	if rootStart < 0xFFFFFFFC {
		miniStream, err = readChain(rootStart)
		if err != nil {
			return nil, err
		}
		if uint64(len(miniStream)) > rootSize {
			miniStream = miniStream[:rootSize]
		}
	}
	readMini := func(start uint32, size uint64) []byte {
		var out []byte
		for sid, seen := start, 0; sid < 0xFFFFFFFC; seen++ {
			if seen > len(miniFAT)+1 {
				break
			}
			off := int(sid) * miniSize
			if off < 0 || off+miniSize > len(miniStream) {
				break
			}
			out = append(out, miniStream[off:off+miniSize]...)
			if int(sid) >= len(miniFAT) {
				break
			}
			sid = miniFAT[sid]
		}
		if uint64(len(out)) > size {
			out = out[:size]
		}
		return out
	}

	streams := make(map[string][]byte)
	for _, e := range entries {
		if e.typ != 2 { // stream objects only
			continue
		}
		var b []byte
		if e.size < uint64(miniCutoff) {
			b = readMini(e.start, e.size)
		} else {
			b, err = readChain(e.start)
			if err != nil {
				return nil, err
			}
			if uint64(len(b)) > e.size {
				b = b[:e.size]
			}
		}
		streams[e.name] = b
	}
	return &File{streams: streams}, nil
}
