package cfb

import (
	"encoding/binary"
	"unicode/utf16"
)

const noStream = 0xFFFFFFFF

// StreamEntry is a named stream to place in a compound file.
type StreamEntry struct {
	Name string
	Data []byte
}

// Build produces a v3 compound file (512-byte sectors, 64-byte mini sectors,
// 4096 cutoff) containing the given streams. Streams smaller than the cutoff go
// in the mini stream; larger ones get their own regular-FAT chains. It is used
// to create fixtures and to (re)produce encrypted Office containers.
func Build(entries []StreamEntry) []byte {
	const sectorSize, miniSize, cutoff = 512, 64, 4096

	type placed struct {
		name  string
		data  []byte
		small bool
		start uint32
		size  uint64
	}
	var ps []placed
	var miniStream []byte
	var miniFAT []uint32

	for _, e := range entries {
		if len(e.Data) < cutoff {
			n := (len(e.Data) + miniSize - 1) / miniSize
			start := uint32(endOfChain)
			if n > 0 {
				start = uint32(len(miniStream) / miniSize)
				padded := make([]byte, n*miniSize)
				copy(padded, e.Data)
				miniStream = append(miniStream, padded...)
				for i := 0; i < n; i++ {
					if i < n-1 {
						miniFAT = append(miniFAT, start+uint32(i)+1)
					} else {
						miniFAT = append(miniFAT, endOfChain)
					}
				}
			}
			ps = append(ps, placed{e.Name, e.Data, true, start, uint64(len(e.Data))})
		} else {
			ps = append(ps, placed{name: e.Name, data: e.Data, size: uint64(len(e.Data))})
		}
	}

	numDirEntries := 1 + len(entries)
	dirSectors := (numDirEntries + 3) / 4
	miniFATSectors := (len(miniFAT)*4 + sectorSize - 1) / sectorSize
	miniStreamSectors := (len(miniStream) + sectorSize - 1) / sectorSize

	var sid uint32
	dirStart := sid
	sid += uint32(dirSectors)
	miniFATStart := uint32(endOfChain)
	if miniFATSectors > 0 {
		miniFATStart = sid
		sid += uint32(miniFATSectors)
	}
	miniStreamStart := uint32(endOfChain)
	if miniStreamSectors > 0 {
		miniStreamStart = sid
		sid += uint32(miniStreamSectors)
	}
	for i := range ps {
		if !ps[i].small {
			n := (len(ps[i].data) + sectorSize - 1) / sectorSize
			ps[i].start = sid
			sid += uint32(n)
		}
	}
	totalData := sid

	const perFatSector = sectorSize / 4
	F := 1
	for (int(totalData)+F+perFatSector-1)/perFatSector > F {
		F++
	}
	fatStart := totalData
	totalSectors := int(totalData) + F

	fat := make([]uint32, totalSectors)
	for i := range fat {
		fat[i] = freeSect
	}
	chain := func(start uint32, n int) {
		for i := 0; i < n; i++ {
			if i < n-1 {
				fat[start+uint32(i)] = start + uint32(i) + 1
			} else {
				fat[start+uint32(i)] = endOfChain
			}
		}
	}
	chain(dirStart, dirSectors)
	if miniFATSectors > 0 {
		chain(miniFATStart, miniFATSectors)
	}
	if miniStreamSectors > 0 {
		chain(miniStreamStart, miniStreamSectors)
	}
	for _, p := range ps {
		if !p.small {
			chain(p.start, (len(p.data)+sectorSize-1)/sectorSize)
		}
	}
	for i := 0; i < F; i++ {
		fat[int(fatStart)+i] = fatSect
	}

	out := make([]byte, 512+totalSectors*sectorSize)
	copy(out[0:8], sig)
	binary.LittleEndian.PutUint16(out[26:], 3)      // major version
	binary.LittleEndian.PutUint16(out[28:], 0xFFFE) // byte order
	binary.LittleEndian.PutUint16(out[30:], 9)      // sector shift => 512
	binary.LittleEndian.PutUint16(out[32:], 6)      // mini sector shift => 64
	binary.LittleEndian.PutUint32(out[44:], uint32(F))
	binary.LittleEndian.PutUint32(out[48:], dirStart)
	binary.LittleEndian.PutUint32(out[56:], cutoff)
	if miniFATSectors > 0 {
		binary.LittleEndian.PutUint32(out[60:], miniFATStart)
		binary.LittleEndian.PutUint32(out[64:], uint32(miniFATSectors))
	} else {
		binary.LittleEndian.PutUint32(out[60:], endOfChain)
	}
	binary.LittleEndian.PutUint32(out[68:], endOfChain) // first DIFAT
	for i := 0; i < 109; i++ {
		v := uint32(freeSect)
		if i < F {
			v = fatStart + uint32(i)
		}
		binary.LittleEndian.PutUint32(out[76+i*4:], v)
	}

	// Directory.
	dirBuf := make([]byte, dirSectors*sectorSize)
	writeEntry := func(idx int, name string, typ byte, start uint32, size uint64, child uint32) {
		off := idx * 128
		u := utf16.Encode([]rune(name))
		for j, c := range u {
			binary.LittleEndian.PutUint16(dirBuf[off+j*2:], c)
		}
		binary.LittleEndian.PutUint16(dirBuf[off+64:], uint16((len(u)+1)*2))
		dirBuf[off+66] = typ
		dirBuf[off+67] = 1 // color
		binary.LittleEndian.PutUint32(dirBuf[off+68:], noStream)
		binary.LittleEndian.PutUint32(dirBuf[off+72:], noStream)
		binary.LittleEndian.PutUint32(dirBuf[off+76:], child)
		binary.LittleEndian.PutUint32(dirBuf[off+116:], start)
		binary.LittleEndian.PutUint64(dirBuf[off+120:], size)
	}
	child := uint32(noStream)
	if len(entries) > 0 {
		child = 1
	}
	writeEntry(0, "Root Entry", 5, miniStreamStart, uint64(len(miniStream)), child)
	for i, p := range ps {
		writeEntry(1+i, p.name, 2, p.start, p.size, noStream)
	}
	copy(out[512+int(dirStart)*sectorSize:], dirBuf)

	if miniFATSectors > 0 {
		mb := make([]byte, miniFATSectors*sectorSize)
		for i := range mb {
			mb[i] = 0xFF
		}
		for i, v := range miniFAT {
			binary.LittleEndian.PutUint32(mb[i*4:], v)
		}
		copy(out[512+int(miniFATStart)*sectorSize:], mb)
	}
	if miniStreamSectors > 0 {
		copy(out[512+int(miniStreamStart)*sectorSize:], miniStream)
	}
	for _, p := range ps {
		if !p.small {
			copy(out[512+int(p.start)*sectorSize:], p.data)
		}
	}
	fatBuf := make([]byte, F*sectorSize)
	for i := range fatBuf {
		fatBuf[i] = 0xFF
	}
	for i, v := range fat {
		binary.LittleEndian.PutUint32(fatBuf[i*4:], v)
	}
	copy(out[512+int(fatStart)*sectorSize:], fatBuf)
	return out
}
