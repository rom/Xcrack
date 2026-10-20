package archive

import (
	"io"

	"github.com/rom/xcrypto"
	"github.com/rom/xcrypto/scheme/rar5"
	"github.com/rom/xfileformats"
)

// rar5Prefix bounds how much of a RAR5 archive head we read to locate the crypt
// record. The record lives in the archive header (-hp) or the first file header
// (-p), both near the start, so a modest prefix is enough and keeps the fast
// verifier allocation-bounded on hostile input.
const rar5Prefix = 64 << 10

var rar5Sig = []byte("Rar!\x1a\x07\x01\x00")

// parseRAR5Crypt reads a bounded prefix of a RAR5 archive and returns the first
// password-check crypt record it finds (the archive HEAD_CRYPT for -hp, or a
// file header's FHEXTRA_CRYPT for -p). RAR uses one password for the whole
// archive, so any record's check value verifies the password for every entry.
// ok is false for RAR4 (no check value), a non-RAR5 input, or a parse failure,
// in which case the caller keeps the (correct but slower) decrypt-and-check
// verifier.
func parseRAR5Crypt(r io.ReaderAt, size int64) (rar5.Params, bool) {
	n := size
	if n <= 0 || n > rar5Prefix {
		n = rar5Prefix
	}
	buf := make([]byte, n)
	read, err := r.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return rar5.Params{}, false
	}
	return findRAR5Crypt(buf[:read])
}

// rar5Challenge builds a reporting/export Challenge from a parsed crypt record.
func rar5Challenge(p rar5.Params) *xcrypto.Challenge {
	return &xcrypto.Challenge{
		Scheme: p.SchemeName(),
		KDF:    xcrypto.KDFSpec{Algo: "pbkdf2-hmac-sha256", Iterations: p.Iterations(), Salt: append([]byte(nil), p.Salt...)},
		Cipher: xcrypto.CipherSpec{Algo: "aes-cbc", KeyBits: 256},
		Extra:  map[string][]byte{"pswcheck": append([]byte(nil), p.PswCheck...)},
	}
}

// rar5Accel builds the GPU-offload AccelKDF for a parsed RAR5 crypt record. The
// stored 8-byte check value is a fold of PBKDF2-HMAC-SHA256(password, salt,
// 2^Lg2Count+32, 32), so the batch kernel derives that key and Finish folds and
// compares it (rar5.VerifyDK) — the same authoritative check as the CPU fast
// verifier, so the device can never cause a false positive. nil when the record
// carries no check value (then there is nothing to accelerate against).
func rar5Accel(p rar5.Params) *xfileformats.AccelKDF {
	if len(p.PswCheck) != rar5.PswCheckLen || len(p.Salt) == 0 {
		return nil
	}
	return &xfileformats.AccelKDF{
		PRF:    "sha256",
		Salt:   append([]byte(nil), p.Salt...),
		Iter:   p.AccelIterations(),
		DKLen:  32,
		Finish: func(dk, _ []byte) bool { return rar5.VerifyDK(dk, p) },
	}
}

// --- RAR5 block / vint walker (per the RAR 5.0 format spec) ---

func rarVint(b []byte, off int) (val uint64, n int, ok bool) {
	var shift uint
	for i := 0; off+i < len(b) && i < 10; i++ {
		c := b[off+i]
		val |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return val, i + 1, true
		}
		shift += 7
	}
	return 0, 0, false
}

func findRAR5Crypt(data []byte) (rar5.Params, bool) {
	sig := len(rar5Sig)
	if len(data) < sig || string(data[:sig]) != string(rar5Sig) {
		return rar5.Params{}, false
	}
	off := sig
	for off+4 < len(data) {
		off += 4 // block CRC32
		hsize, hn, ok := rarVint(data, off)
		if !ok || hsize == 0 {
			return rar5.Params{}, false
		}
		off += hn
		if uint64(len(data)-off) < hsize {
			return rar5.Params{}, false // header spills past the prefix we read
		}
		hdr := data[off : off+int(hsize)]
		next := off + int(hsize)

		htype, tn, ok := rarVint(hdr, 0)
		if !ok {
			return rar5.Params{}, false
		}
		hflags, fn, ok := rarVint(hdr, tn)
		if !ok {
			return rar5.Params{}, false
		}
		pos := tn + fn
		var extraSize uint64
		if hflags&0x0001 != 0 {
			extraSize, fn, ok = rarVint(hdr, pos)
			if !ok {
				return rar5.Params{}, false
			}
			pos += fn
		}
		if hflags&0x0002 != 0 {
			_, fn, ok = rarVint(hdr, pos)
			if !ok {
				return rar5.Params{}, false
			}
			pos += fn
		}

		switch htype {
		case 4: // archive HEAD_CRYPT (-hp)
			if p, ok := parseRAR5CryptRecord(hdr[pos:], false); ok {
				return p, true
			}
		case 2: // file header (-p): crypt record is in the extra area
			if extraSize > 0 {
				body := hdr[pos:]
				if uint64(len(body)) >= extraSize {
					if p, ok := scanRAR5Extra(body[uint64(len(body))-extraSize:]); ok {
						return p, true
					}
				}
			}
		}
		off = next
	}
	return rar5.Params{}, false
}

func scanRAR5Extra(area []byte) (rar5.Params, bool) {
	for pos := 0; pos < len(area); {
		recSize, n, ok := rarVint(area, pos)
		if !ok || recSize == 0 {
			return rar5.Params{}, false
		}
		start := pos + n
		if start+int(recSize) > len(area) {
			return rar5.Params{}, false
		}
		rec := area[start : start+int(recSize)]
		rtype, rn, ok := rarVint(rec, 0)
		if ok && rtype == 1 { // FHEXTRA_CRYPT
			if p, ok := parseRAR5CryptRecord(rec[rn:], true); ok {
				return p, true
			}
		}
		pos = start + int(recSize)
	}
	return rar5.Params{}, false
}

func parseRAR5CryptRecord(rec []byte, withIV bool) (rar5.Params, bool) {
	_, n, ok := rarVint(rec, 0) // EncVersion
	if !ok {
		return rar5.Params{}, false
	}
	pos := n
	encFlags, n, ok := rarVint(rec, pos)
	if !ok {
		return rar5.Params{}, false
	}
	pos += n
	if pos >= len(rec) {
		return rar5.Params{}, false
	}
	lg2 := uint(rec[pos])
	pos++
	if lg2 > rar5.MaxLg2Count {
		// Out-of-spec KDF cost (a corrupt or hostile header): refuse the fast
		// verifier so the engine falls back to the decoder, which rejects it too,
		// rather than building a verifier that runs ~2^lg2 HMAC rounds per guess.
		return rar5.Params{}, false
	}
	if pos+rar5.SaltLen > len(rec) {
		return rar5.Params{}, false
	}
	salt := rec[pos : pos+rar5.SaltLen]
	pos += rar5.SaltLen
	if withIV {
		pos += 16
	}
	if encFlags&0x0001 == 0 { // no password-check value present
		return rar5.Params{}, false
	}
	if pos+rar5.PswCheckLen > len(rec) {
		return rar5.Params{}, false
	}
	return rar5.Params{
		Salt:     append([]byte(nil), salt...),
		Lg2Count: lg2,
		PswCheck: append([]byte(nil), rec[pos:pos+rar5.PswCheckLen]...),
	}, true
}
