package msoffice

import (
	"bytes"
	"io"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/officebinary"
	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/internal/cfb"
)

// BIFF record numbers. [MS-XLS] 2.3.
const (
	biffBOF          = 0x0809 // 2057
	biffEOF          = 0x000A // 10
	biffFilePass     = 0x002F // 47
	biffInterfaceHdr = 0x00E1 // 225
	biffRRDHead      = 0x0138 // 312
	biffUsrExcl      = 0x0194 // 404
	biffFileLock     = 0x0195 // 405
	biffRRDInfo      = 0x0196 // 406
	biffBoundSheet8  = 0x0085 // 133

	xlsBlockLen = 0x400 // Excel RC4 rekey block size (1024)
)

// biffRecords walks the BIFF record stream, yielding (num, size, body) with the
// body clamped to the bytes actually present (hostile input may truncate).
func biffRecords(wb []byte, fn func(num uint16, body []byte) bool) {
	p := 0
	for p+4 <= len(wb) {
		num := u16(wb, p)
		size := int(u16(wb, p+2))
		start := p + 4
		end := start + size
		if end > len(wb) {
			end = len(wb)
		}
		if !fn(num, wb[start:end]) {
			return
		}
		p = start + size
	}
}

// xlsEntries locates the Excel FilePass record and returns a single entry for
// the decrypted Workbook stream.
func xlsEntries(cf *cfb.File) ([]*xfileformats.Entry, error) {
	wb, ok := cf.Stream("Workbook")
	if !ok {
		wb, ok = cf.Stream("Book")
	}
	if !ok || len(wb) < 4 {
		return nil, xfileformats.ErrUnsupported
	}
	if u16(wb, 0) != biffBOF {
		return nil, xfileformats.ErrUnsupported
	}

	ei := &encInfo{}
	found := false
	done := false
	biffRecords(wb, func(num uint16, body []byte) bool {
		switch num {
		case biffBOF:
			return true // skip the leading BOF
		case biffFilePass:
			found = parseFilePass(body, ei)
			done = true
			return false
		case biffEOF:
			done = true // globals substream ended without a FilePass
			return false
		}
		return true
	})
	if !done || !found {
		return nil, xfileformats.ErrNotEncrypted
	}

	raw := append([]byte{}, wb...)
	entry := &xfileformats.Entry{
		Path:      "Workbook",
		Size:      int64(len(raw)),
		Encrypted: true,
		Challenge: ei.challenge(),
		Verify:    ei.verify,
		Open: func(pw []byte) (io.Reader, error) {
			out, err := xlsDecrypt(ei, pw, raw)
			if err != nil {
				return nil, err
			}
			return bytes.NewReader(out), nil
		},
	}
	return []*xfileformats.Entry{entry}, nil
}

// parseFilePass reads a FilePass record body: wEncryptionType(2) then either the
// XOR key+verifier or the RC4 EncryptionInfo. [MS-XLS] 2.4.117.
func parseFilePass(body []byte, ei *encInfo) bool {
	if len(body) < 2 {
		return false
	}
	encType := u16(body, 0)
	rest := body[2:]
	switch encType {
	case 0x0000: // XOR obfuscation
		if len(rest) < 4 {
			return false
		}
		ei.kind = "xor"
		ei.xorVerifier = u16(rest, 2) // key(2) then verificationBytes(2)
		return true
	case 0x0001: // RC4 family
		return parseVersionedRC4(rest, ei)
	}
	return false
}

// xlsDecrypt rebuilds the decrypted Workbook stream. Record headers and a small
// set of records are stored in the clear; the rest of each record body is
// encrypted. The keystream runs over a reconstruction where the clear bytes are
// zeroed, so its position tracks the real stream layout. [MS-XLS] 2.3 /
// [MS-OFFCRYPTO] 2.3.5.4.
func xlsDecrypt(ei *encInfo, pw, wb []byte) ([]byte, error) {
	plain := make([]int, 0, len(wb))
	cipher := make([]byte, 0, len(wb))
	appendHeader := func(num uint16, size int, literalHeader bool) {
		if literalHeader {
			plain = append(plain, int(num&0xFF), int(num>>8), int(size&0xFF), int(size>>8))
		} else { // FilePass: blank the record number, keep the size
			plain = append(plain, 0, 0, int(size&0xFF), int(size>>8))
		}
		cipher = append(cipher, 0, 0, 0, 0)
	}

	biffRecords(wb, func(num uint16, body []byte) bool {
		size := len(body)
		switch num {
		case biffFilePass:
			appendHeader(num, size, false)
			for range body {
				plain = append(plain, 0)
				cipher = append(cipher, 0)
			}
		case biffBOF, biffUsrExcl, biffFileLock, biffInterfaceHdr, biffRRDInfo, biffRRDHead:
			appendHeader(num, size, true)
			for _, b := range body { // kept in the clear
				plain = append(plain, int(b))
				cipher = append(cipher, 0)
			}
		case biffBoundSheet8:
			appendHeader(num, size, true)
			n := 4
			if n > size {
				n = size
			}
			for _, b := range body[:n] { // lbPlyPos kept in the clear
				plain = append(plain, int(b))
				cipher = append(cipher, 0)
			}
			for _, b := range body[n:] {
				plain = append(plain, -2)
				cipher = append(cipher, b)
			}
		default:
			appendHeader(num, size, true)
			for _, b := range body {
				plain = append(plain, -1)
				cipher = append(cipher, b)
			}
		}
		return true
	})

	if ei.kind == "xor" {
		out, ok := officebinary.DecryptXORMethod1(pw, cipher, plain)
		if !ok {
			return nil, xcrypto.ErrWrongPassword
		}
		return out, nil
	}

	dec, err := ei.decryptBlocks(pw, cipher, xlsBlockLen, 0)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plain))
	for i, c := range plain {
		if c >= 0 {
			out[i] = byte(c)
		} else {
			out[i] = dec[i]
		}
	}
	return out, nil
}
