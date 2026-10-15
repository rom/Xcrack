package msoffice

import (
	"bytes"
	"io"

	"github.com/rom/xcrypto"
	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/internal/cfb"
)

// Word FIB constants. [MS-DOC] 2.5.1 (FibBase).
const (
	fibWIdent   = 0xA5EC // FibBase.wIdent magic
	fibLength   = 0x44   // bytes preserved unencrypted at the head of WordDocument
	docBlockLen = 0x200  // Word RC4 rekey block size
)

// docEntries locates the Word encryption parameters in the FIB and returns one
// entry per encrypted stream (WordDocument, the table stream, and Data).
func docEntries(cf *cfb.File) ([]*xfileformats.Entry, error) {
	wd, ok := cf.Stream("WordDocument")
	if !ok || len(wd) < 32 {
		return nil, xfileformats.ErrUnsupported
	}
	if u16(wd, 0) != fibWIdent {
		return nil, xfileformats.ErrUnsupported
	}
	flags := u16(wd, 10)
	fEncrypted := flags&(1<<8) != 0
	fWhichTblStm := flags&(1<<9) != 0
	fObfuscation := flags&(1<<15) != 0
	if !fEncrypted {
		return nil, xfileformats.ErrNotEncrypted
	}

	ei := &encInfo{}
	if fObfuscation {
		// Word XOR obfuscation: the 16-bit verifier is the low word of lKey.
		// The password is recoverable, but reconstructing the obfuscated
		// document body is not implemented (no reference oracle), so we expose
		// a verify-only entry rather than wrong plaintext.
		ei.kind = "xor"
		ei.xorVerifier = uint16(u32(wd, 14))
		return []*xfileformats.Entry{verifyOnlyEntry("WordDocument", ei)}, nil
	}

	tbl := "0Table"
	if fWhichTblStm {
		tbl = "1Table"
	}
	ts, ok := cf.Stream(tbl)
	if !ok {
		return nil, xfileformats.ErrMalformed
	}
	if !parseVersionedRC4(ts, ei) {
		return nil, xfileformats.ErrUnsupported
	}

	entries := []*xfileformats.Entry{
		docStreamEntry(ei, "WordDocument", wd, true),
		docStreamEntry(ei, tbl, ts, false),
	}
	if data, ok := cf.Stream("Data"); ok && len(data) > 0 {
		entries = append(entries, docStreamEntry(ei, "Data", data, false))
	}
	return entries, nil
}

// docStreamEntry builds an entry for one Word stream. When preserveFIB is set
// (the WordDocument stream), the first 0x44 bytes are kept as plaintext with
// the FibBase encryption flags and lKey cleared, matching how Word stores the
// FIB; the RC4 keystream still advances across those bytes. [MS-OFFCRYPTO]
// 2.3.5.4.
func docStreamEntry(ei *encInfo, name string, stream []byte, preserveFIB bool) *xfileformats.Entry {
	raw := append([]byte{}, stream...)
	open := func(pw []byte) (io.Reader, error) {
		dec, err := ei.decryptBlocks(pw, raw, docBlockLen, 0)
		if err != nil {
			return nil, err
		}
		if preserveFIB && len(raw) >= fibLength {
			head := append([]byte{}, raw[:fibLength]...)
			// Clear fEncrypted (bit 8) and fObfuscation (bit 15), zero lKey.
			f := u16(head, 10) &^ (1 << 8) &^ (1 << 15)
			head[10] = byte(f)
			head[11] = byte(f >> 8)
			head[14], head[15], head[16], head[17] = 0, 0, 0, 0
			out := append(head, dec[fibLength:]...)
			return bytes.NewReader(out), nil
		}
		return bytes.NewReader(dec), nil
	}
	return &xfileformats.Entry{
		Path:      name,
		Size:      int64(len(raw)),
		Encrypted: true,
		Challenge: ei.challenge(),
		Verify:    ei.verify,
		Open:      open,
	}
}

// verifyOnlyEntry exposes an entry whose password can be verified but whose
// content cannot be reconstructed (used for Word XOR obfuscation).
func verifyOnlyEntry(name string, ei *encInfo) *xfileformats.Entry {
	return &xfileformats.Entry{
		Path:      name,
		Encrypted: true,
		Challenge: ei.challenge(),
		Verify:    ei.verify,
		Open: func([]byte) (io.Reader, error) {
			return nil, xcrypto.ErrUnsupported
		},
	}
}
