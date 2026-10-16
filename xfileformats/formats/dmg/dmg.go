// Package dmg recovers the password of an Apple encrypted disk image from a
// dmg2john `$dmg$` hash line, the portable representation a real .dmg is reduced
// to by `dmg2john image.dmg`. Both header versions are handled by the
// xcrypto/scheme/dmg verifier, which is cross-validated against John the
// Ripper's authoritative vectors.
//
// Only the dmg2john text line is consumed here, not the raw .dmg container: the
// crypto is oracle-validated, but parsing the on-disk `encrcdsa`/koly header has
// no test sample in this build to validate against, so it is deferred. The
// standard workflow is `dmg2john image.dmg > h` then `xcrack h -w wordlist`,
// matching how John/hashcat users already operate; the recovered password is
// the deliverable.
package dmg

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/rom/xcrypto"
	xdmg "github.com/rom/xcrypto/scheme/dmg"
	"github.com/rom/xfileformats"
)

// maxProbe bounds how much of the input we read to find a $dmg$ line. A v2 line
// embeds an 8 KiB data chunk (~16 KiB hex) plus a spare chunk, so this is
// generous while still bounded.
const maxProbe = 1 << 20

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

// Detect recognizes a dmg2john hash line by its "$dmg$" marker anywhere in the
// peek (dmg2john prefixes the image filename, e.g. "image.dmg:$dmg$2*...").
func (f *Format) Detect(peek []byte) (float64, bool) {
	if bytes.Contains(peek, []byte("$dmg$")) {
		return 0.99, true
	}
	return 0, false
}

// Probe reads the first $dmg$ line and parses it into a verification Challenge.
func (f *Format) Probe(r io.ReaderAt, size int64) (*xcrypto.Challenge, error) {
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
