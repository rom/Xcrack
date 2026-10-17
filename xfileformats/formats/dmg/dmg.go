// Package dmg recovers the password of an Apple encrypted disk image. It reads
// a real on-disk `encrcdsa` v2 container directly (the modern format Disk
// Utility / hdiutil produce, AES-128 or AES-256) and also accepts the portable
// dmg2john `$dmg$` hash line (`dmg2john image.dmg`). Both feed the
// xcrypto/scheme/dmg verifier, which is cross-validated against John the
// Ripper's authoritative vectors and against real macOS-produced images.
//
// The on-disk parser follows the dmg2john / vilefault header layout
// (filevault.h) and is validated against real AES-128 and AES-256 images with a
// known password. Only the header, key blob and one data chunk are read (via
// ReadAt), never the whole image. The recovered password is the deliverable;
// the image is not mounted or wholesale-decrypted.
package dmg

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/rom/xcrypto"
	xdmg "github.com/rom/xcrypto/scheme/dmg"
	"github.com/rom/xfileformats"
)

const (
	// maxProbe bounds how much of a $dmg$ TEXT input we read to find the line.
	maxProbe = 1 << 20
	// encrcdsa on-disk geometry (big-endian, from filevault.h / dmg2john).
	encHdrLen     = 76   // sizeof(cencrypted_v2_header)
	encPtrLen     = 20   // sizeof(cencrypted_v2_key_header_pointer)
	encPWFixed    = 104  // password header minus the trailing keyblob pointer
	encChunkUnit  = 4096 // image data chunk size
	encMaxKeyblob = 1024 // sanity bound on the wrapped key blob
	encMaxChunk   = 1 << 16
)

var encMagic = []byte("encrcdsa")

// Format recovers the password behind a dmg2john $dmg$ hash line.
type Format struct{}

// New returns a dmg Format.
func New() *Format { return &Format{} }

// Register adds the format to a registry.
func Register(r *xfileformats.Registry) { r.Register(New()) }

// Name implements xfileformats.Format.
func (f *Format) Name() string { return "dmg" }

// Caps implements xfileformats.Format: the hash line is a whole-"file"
// password challenge.
func (f *Format) Caps() xfileformats.Caps { return xfileformats.Caps{Encrypted: true} }

// Detect recognizes a real encrypted DMG by its "encrcdsa" magic at offset 0,
// or a dmg2john hash line by its "$dmg$" marker anywhere in the peek (dmg2john
// prefixes the image filename, e.g. "image.dmg:$dmg$2*...").
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.HasPrefix(peek, encMagic) {
		return 0.99, true
	}
	if bytes.Contains(peek, []byte("$dmg$")) {
		return 0.99, true
	}
	return 0, false
}

// Probe parses either a real encrcdsa v2 container or a dmg2john $dmg$ line into
// a verification Challenge.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
	magic := make([]byte, len(encMagic))
	if _, err := r.ReadAt(magic, 0); err == nil && bytes.Equal(magic, encMagic) {
		p, perr := probeEncrcdsaV2(r, size)
		if perr != nil {
			return nil, perr
		}
		return &xcrypto.Challenge{Scheme: p.SchemeName(), Extra: encodeParams(p)}, nil
	}

	n := size
	if n <= 0 || n > maxProbe {
		n = maxProbe
	}
	buf := make([]byte, n)
	read, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, xfileformats.ErrMalformed
	}
	buf = buf[:read]
	line := firstDMGLine(buf)
	if line == "" {
		return nil, xfileformats.ErrNotEncrypted
	}
	p, err := xdmg.ParseJohn(line)
	if err != nil {
		return nil, xfileformats.ErrUnsupported
	}
	return &xcrypto.Challenge{Scheme: p.SchemeName(), Extra: encodeParams(p)}, nil
}

// probeEncrcdsaV2 parses a real on-disk encrcdsa v2 header (big-endian, per
// filevault.h) into DMG v2 Params, reading only the header region, the wrapped
// key blob, and one data chunk via ReadAt — never the whole image.
func probeEncrcdsaV2(r io.ReaderAt, size int64) (xdmg.Params, error) {
	var p xdmg.Params
	hdr := make([]byte, encHdrLen)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return p, xfileformats.ErrMalformed
	}
	if !bytes.Equal(hdr[:8], encMagic) || binary.BigEndian.Uint32(hdr[8:]) != 2 {
		return p, xfileformats.ErrUnsupported
	}
	datasize := binary.BigEndian.Uint64(hdr[56:])
	dataoffset := binary.BigEndian.Uint64(hdr[64:])
	keycount := binary.BigEndian.Uint32(hdr[72:])
	if keycount == 0 || keycount > 64 || datasize < encChunkUnit || int64(dataoffset) >= size {
		return p, xfileformats.ErrMalformed
	}

	// Walk the key-header pointers for the password key (header_type == 1).
	ptr := make([]byte, encPtrLen)
	var pwOffset int64 = -1
	for i := uint32(0); i < keycount; i++ {
		if _, err := r.ReadAt(ptr, int64(encHdrLen)+int64(encPtrLen)*int64(i)); err != nil {
			return p, xfileformats.ErrMalformed
		}
		if binary.BigEndian.Uint32(ptr[0:]) == 1 { // header_type: password
			pwOffset = int64(binary.BigEndian.Uint32(ptr[8:])) // header_offset
			break
		}
	}
	if pwOffset < 0 || pwOffset+encPWFixed > size {
		return p, xfileformats.ErrUnsupported
	}

	pw := make([]byte, encPWFixed)
	if _, err := r.ReadAt(pw, pwOffset); err != nil {
		return p, xfileformats.ErrMalformed
	}
	iter := int(binary.BigEndian.Uint32(pw[8:]))
	saltSize := int(binary.BigEndian.Uint32(pw[12:]))
	keyblobSize := int(binary.BigEndian.Uint32(pw[100:]))
	if saltSize < 1 || saltSize > 32 || keyblobSize < 1 || keyblobSize > encMaxKeyblob {
		return p, xfileformats.ErrMalformed
	}
	keyblob := make([]byte, keyblobSize)
	if _, err := r.ReadAt(keyblob, pwOffset+encPWFixed); err != nil {
		return p, xfileformats.ErrMalformed
	}

	// The data chunk dmg2john uses: the second-to-last 4096-byte chunk, which may
	// be a partial block (the verifier handles that).
	cno := (int64(datasize)+encChunkUnit-1)/encChunkUnit - 2
	if cno < 0 {
		cno = 0
	}
	chunkLen := int64(datasize) - cno*encChunkUnit
	if chunkLen < 1 || chunkLen > encMaxChunk {
		return p, xfileformats.ErrMalformed
	}
	start := int64(dataoffset) + cno*encChunkUnit
	if start+chunkLen > size {
		return p, xfileformats.ErrMalformed
	}
	chunk := make([]byte, chunkLen)
	if _, err := r.ReadAt(chunk, start); err != nil {
		return p, xfileformats.ErrMalformed
	}

	p.Version = 2
	p.Iterations = iter
	p.Salt = pw[16 : 16+saltSize]
	p.IV = pw[52:84] // iv[32], iv_size at +48
	p.EncryptedKeyblob = keyblob
	p.ChunkNo = uint32(cno)
	p.Chunk = chunk
	return p, nil
}

// Verify tests one candidate against the parsed DMG parameters.
func (f *Format) Verify(ch *xcrypto.Challenge, password []byte) (bool, []byte, error) {
	p := decodeParams(ch.Extra)
	ok, err := xdmg.Verify(password, p)
	if err != nil || !ok {
		return false, nil, err
	}
	return true, append([]byte(nil), password...), nil
}

// Decrypt has nothing to surface — a $dmg$ line carries no image payload, and
// the recovered password is the deliverable — so it returns an empty reader.
func (f *Format) Decrypt(r io.ReaderAt, size int64, ch *xcrypto.Challenge, key []byte) (io.Reader, error) {
	return bytes.NewReader(nil), nil
}

// AccelKDF exposes the image's single PBKDF2-HMAC-SHA1 derivation so the engine
// can offload the keyspace sweep to a GPU tier. Both DMG versions derive one
// 32-byte key over the fixed 20-byte salt; Finish re-runs the authoritative
// v1/v2 verifier on the derived key, so a GPU-derived key yields the same
// verdict as the CPU path and acceleration can never cause a false positive.
// This makes dmg.Format an xfileformats.Accelerable.
func (f *Format) AccelKDF(ch *xcrypto.Challenge) (xfileformats.AccelKDF, bool) {
	p := decodeParams(ch.Extra)
	if p.Version != 1 && p.Version != 2 {
		return xfileformats.AccelKDF{}, false
	}
	return xfileformats.AccelKDF{
		Salt:  p.Salt20(),
		Iter:  p.EffectiveIterations(),
		DKLen: xdmg.DKLen,
		Finish: func(dk, _ []byte) bool {
			ok, _ := xdmg.VerifyWithDK(dk, p)
			return ok
		},
	}, true
}

// firstDMGLine returns the first line containing a $dmg$ marker, or "".
func firstDMGLine(buf []byte) string {
	for _, ln := range bytes.Split(buf, []byte("\n")) {
		if bytes.Contains(ln, []byte("$dmg$")) {
			return string(ln)
		}
	}
	return ""
}

func u32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func be32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// encodeParams serializes the parsed DMG parameters into Challenge.Extra so
// Verify need not re-parse the (large) hash line per candidate.
func encodeParams(p xdmg.Params) map[string][]byte {
	e := map[string][]byte{
		"ver":  {byte(p.Version)},
		"salt": p.Salt,
		"iter": u32(uint32(p.Iterations)),
	}
	if p.Version == 1 {
		e["waes"] = p.WrappedAESKey
		e["whmac"] = p.WrappedHMACKey
	} else {
		e["iv"] = p.IV
		e["keyblob"] = p.EncryptedKeyblob
		e["cno"] = u32(p.ChunkNo)
		e["chunk"] = p.Chunk
	}
	return e
}

func decodeParams(e map[string][]byte) xdmg.Params {
	p := xdmg.Params{Salt: e["salt"], Iterations: int(be32(e["iter"]))}
	if v := e["ver"]; len(v) > 0 {
		p.Version = int(v[0])
	}
	if p.Version == 1 {
		p.WrappedAESKey = e["waes"]
		p.WrappedHMACKey = e["whmac"]
	} else {
		p.IV = e["iv"]
		p.EncryptedKeyblob = e["keyblob"]
		p.ChunkNo = be32(e["cno"])
		p.Chunk = e["chunk"]
	}
	return p
}
