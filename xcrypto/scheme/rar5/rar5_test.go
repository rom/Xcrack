package rar5

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto/prim"
)

// TestAccelDerivation proves the GPU-offload path is byte-identical to the CPU
// fast verifier: the +32 check-value snapshot equals a standard
// PBKDF2-HMAC-SHA256(password, salt, 2^Lg2Count+32, 32) run, so a batch kernel
// can derive it and PswCheckFromDK/VerifyDK reproduce the stored 8-byte value.
// Pinned to the same real-archive vector as TestKnownAnswer.
func TestAccelDerivation(t *testing.T) {
	salt, _ := hex.DecodeString("4d09db306505c5cd1b29f0cb4c2bc5aa")
	want, _ := hex.DecodeString("b17fbe6cc603d208")
	p := Params{Salt: salt, Lg2Count: 15, PswCheck: want}

	dk, err := prim.PBKDF2(sha256.New, "opensesame", salt, p.AccelIterations(), 32)
	if err != nil {
		t.Fatal(err)
	}
	if got := PswCheckFromDK(dk); hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("PswCheckFromDK = %x, want %x (accel derivation disagrees with CPU)", got, want)
	}
	if !VerifyDK(dk, p) {
		t.Fatal("VerifyDK(correct) = false")
	}
	wrong, _ := prim.PBKDF2(sha256.New, "wrongpassword", salt, p.AccelIterations(), 32)
	if VerifyDK(wrong, p) {
		t.Fatal("VerifyDK(wrong) = true, want false")
	}
}

// TestKnownAnswer pins the derivation to a vector taken from a real WinRAR/`rar`
// -hp archive (password "opensesame"): the computed check value must equal the
// one stored in the archive header, and a wrong password must not.
func TestKnownAnswer(t *testing.T) {
	salt, _ := hex.DecodeString("4d09db306505c5cd1b29f0cb4c2bc5aa")
	want, _ := hex.DecodeString("b17fbe6cc603d208")
	p := Params{Salt: salt, Lg2Count: 15, PswCheck: want}
	if !Verify("opensesame", p) {
		got := PswCheckValue("opensesame", salt, 15)
		t.Fatalf("Verify(correct) = false; got pswcheck %x want %x", got, want)
	}
	if Verify("wrongpassword", p) {
		t.Fatal("Verify(wrong) = true, want false")
	}
}

// TestRarCLICrossValidation generates fresh RAR5 archives with the real `rar`
// tool (header-encrypted and data-only) and confirms the parsed check value
// verifies the known password and rejects a wrong one. Skipped when `rar` is
// not installed.
func TestRarCLICrossValidation(t *testing.T) {
	rarBin, err := exec.LookPath("rar")
	if err != nil {
		t.Skip("rar CLI not available")
	}
	dir := t.TempDir()
	payload := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(payload, []byte("rar5 cross-validation payload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const pw = "Sommar2024!"
	for _, tc := range []struct {
		name, flag string
	}{
		{"header-encrypted", "-hp" + pw},
		{"data-only", "-p" + pw},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arc := filepath.Join(dir, tc.name+".rar")
			cmd := exec.Command(rarBin, "a", tc.flag, "-idq", arc, payload)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("rar a: %v\n%s", err, out)
			}
			data, err := os.ReadFile(arc)
			if err != nil {
				t.Fatal(err)
			}
			p, ok := findCrypt(data)
			if !ok {
				t.Fatalf("no RAR5 crypt record parsed from %s", tc.name)
			}
			if !Verify(pw, p) {
				t.Fatalf("Verify(correct) failed for %s (salt=%x lg2=%d check=%x)", tc.name, p.Salt, p.Lg2Count, p.PswCheck)
			}
			if Verify("not-the-password", p) {
				t.Fatalf("Verify(wrong) succeeded for %s", tc.name)
			}
		})
	}
}

// --- a minimal in-test RAR5 crypt-record finder (mirrors the format-layer
// parser) so the scheme can be cross-validated without importing xfileformats. ---

func readVint(b []byte, off int) (val uint64, n int, ok bool) {
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

// findCrypt walks RAR5 blocks for a crypt record: the archive HEAD_CRYPT (type
// 4, -hp) or a file header's FHEXTRA_CRYPT extra record (type 1, -p).
func findCrypt(data []byte) (Params, bool) {
	const sigLen = 8
	if len(data) < sigLen || string(data[:sigLen]) != "Rar!\x1a\x07\x01\x00" {
		return Params{}, false
	}
	off := sigLen
	for off+4 < len(data) {
		off += 4 // CRC32
		hsize, n, ok := readVint(data, off)
		if !ok || hsize == 0 {
			return Params{}, false
		}
		off += n
		hdr := data[off:]
		if uint64(len(hdr)) < hsize {
			return Params{}, false
		}
		hdr = hdr[:hsize]
		next := off + int(hsize)

		htype, tn, ok := readVint(hdr, 0)
		if !ok {
			return Params{}, false
		}
		hflags, fn, ok := readVint(hdr, tn)
		if !ok {
			return Params{}, false
		}
		pos := tn + fn
		var extraSize uint64
		if hflags&0x0001 != 0 { // extra area present
			extraSize, n, ok = readVint(hdr, pos)
			if !ok {
				return Params{}, false
			}
			pos += n
		}
		if hflags&0x0002 != 0 { // data area present (size vint, data is outside header)
			_, n, ok = readVint(hdr, pos)
			if !ok {
				return Params{}, false
			}
			pos += n
		}

		switch htype {
		case 4: // archive HEAD_CRYPT (-hp): crypt record is the header body
			if p, ok := parseCryptRecord(hdr[pos:], false); ok {
				return p, true
			}
		case 2: // file header (-p): crypt record lives in the extra area
			if extraSize > 0 {
				body := hdr[pos:]
				if uint64(len(body)) >= extraSize {
					if p, ok := scanExtra(body[uint64(len(body))-extraSize:]); ok {
						return p, true
					}
				}
			}
		}
		off = next
	}
	return Params{}, false
}

// scanExtra walks a file header's extra area for a FHEXTRA_CRYPT (type 1) record.
func scanExtra(area []byte) (Params, bool) {
	for pos := 0; pos < len(area); {
		recSize, n, ok := readVint(area, pos)
		if !ok || recSize == 0 {
			return Params{}, false
		}
		recStart := pos + n
		if recStart+int(recSize) > len(area) {
			return Params{}, false
		}
		rec := area[recStart : recStart+int(recSize)]
		rtype, rn, ok := readVint(rec, 0)
		if ok && rtype == 1 { // FHEXTRA_CRYPT
			if p, ok := parseCryptRecord(rec[rn:], true); ok {
				return p, true
			}
		}
		pos = recStart + int(recSize)
	}
	return Params{}, false
}

// parseCryptRecord parses the common crypt fields. withIV is true for the
// file-level record (which carries a 16-byte IV between salt and check value);
// the archive HEAD_CRYPT record has no IV.
func parseCryptRecord(rec []byte, withIV bool) (Params, bool) {
	_, n, ok := readVint(rec, 0) // EncVersion
	if !ok {
		return Params{}, false
	}
	pos := n
	encFlags, n, ok := readVint(rec, pos)
	if !ok {
		return Params{}, false
	}
	pos += n
	if pos >= len(rec) {
		return Params{}, false
	}
	lg2 := uint(rec[pos])
	pos++
	if pos+SaltLen > len(rec) {
		return Params{}, false
	}
	salt := rec[pos : pos+SaltLen]
	pos += SaltLen
	if withIV {
		pos += 16 // skip IV
	}
	if encFlags&0x0001 == 0 { // CHFL_CRYPT_PSWCHECK not set: no fast check
		return Params{}, false
	}
	if pos+PswCheckLen > len(rec) {
		return Params{}, false
	}
	check := rec[pos : pos+PswCheckLen]
	return Params{Salt: append([]byte(nil), salt...), Lg2Count: lg2, PswCheck: append([]byte(nil), check...)}, true
}
