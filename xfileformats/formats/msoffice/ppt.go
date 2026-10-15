package msoffice

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/internal/cfb"
)

// PowerPoint record types. [MS-PPT] 2.13.24.
const (
	pptUserEditAtom        = 0x0FF5
	pptCurrentUserAtom     = 0x0FF6
	pptPersistDirectory    = 0x1772
	pptCryptSession10      = 0x2F14
	pptUserEditWithCrypt   = 0x20 // UserEditAtom.rh.recLen when encrypted
	pptUserEditWithoutCrpt = 0x1C
)

// pptEntries locates the PowerPoint CryptSession10Container (RC4 CryptoAPI only)
// and returns a single entry for the decrypted PowerPoint Document stream.
func pptEntries(cf *cfb.File) ([]*xfileformats.Entry, error) {
	cu, ok := cf.Stream("Current User")
	if !ok || len(cu) < 20 {
		return nil, xfileformats.ErrUnsupported
	}
	ppd, ok := cf.Stream("PowerPoint Document")
	if !ok {
		return nil, xfileformats.ErrUnsupported
	}
	offsetCurrentEdit := int(u32(cu, 16))

	ue, ok := parseUserEdit(ppd, offsetCurrentEdit)
	if !ok {
		return nil, xfileformats.ErrMalformed
	}
	if ue.recLen != pptUserEditWithCrypt {
		return nil, xfileformats.ErrNotEncrypted // not an encrypted presentation
	}

	dir, order, ok := persistDirectory(ppd, ue)
	if !ok {
		return nil, xfileformats.ErrMalformed
	}
	cryptOff, ok := dir[ue.encryptSessionPersistIDRef]
	if !ok {
		return nil, xfileformats.ErrMalformed
	}
	// CryptSession10Container: rh(8) + EncryptionInfo (version + header + verifier).
	if cryptOff < 0 || cryptOff+8 > len(ppd) {
		return nil, xfileformats.ErrMalformed
	}
	recType := u16(ppd, cryptOff+2)
	recLen := int(u32(ppd, cryptOff+4))
	if recType != pptCryptSession10 || cryptOff+8+recLen > len(ppd) || recLen < 4 {
		return nil, xfileformats.ErrMalformed
	}
	ei := &encInfo{}
	if !parseVersionedRC4(ppd[cryptOff+8:cryptOff+8+recLen], ei) || ei.kind != "rc4-cryptoapi" {
		return nil, xfileformats.ErrUnsupported
	}

	raw := append([]byte{}, ppd...)
	entry := &xfileformats.Entry{
		Path:      "PowerPoint Document",
		Size:      int64(len(raw)),
		Encrypted: true,
		Challenge: ei.challenge(),
		Verify:    ei.verify,
		Open: func(pw []byte) (io.Reader, error) {
			out, err := pptDecrypt(ei, pw, raw, offsetCurrentEdit, ue, dir, order)
			if err != nil {
				return nil, err
			}
			return bytes.NewReader(out), nil
		},
	}
	return []*xfileformats.Entry{entry}, nil
}

type userEditAtom struct {
	offset                     int
	recLen                     uint32
	offsetPersistDirectory     int
	encryptSessionPersistIDRef uint32
}

func parseUserEdit(ppd []byte, off int) (userEditAtom, bool) {
	var ue userEditAtom
	if off < 0 || off+8 > len(ppd) {
		return ue, false
	}
	if u16(ppd, off+2) != pptUserEditAtom {
		return ue, false
	}
	recLen := u32(ppd, off+4)
	ue.offset = off
	ue.recLen = recLen
	if off+24 > len(ppd) {
		return ue, false
	}
	ue.offsetPersistDirectory = int(u32(ppd, off+20))
	if recLen == pptUserEditWithCrypt {
		if off+40 > len(ppd) {
			return ue, false
		}
		ue.encryptSessionPersistIDRef = u32(ppd, off+36)
	}
	return ue, true
}

// persistDirectory builds the persist-object directory from the current edit's
// PersistDirectoryAtom (matching the reference, which reads only the current
// edit). It returns the id->offset map and the ids in first-seen order.
func persistDirectory(ppd []byte, ue userEditAtom) (map[uint32]int, []uint32, bool) {
	op := ue.offsetPersistDirectory
	if op < 0 || op+8 > len(ppd) {
		return nil, nil, false
	}
	if u16(ppd, op+2) != pptPersistDirectory {
		return nil, nil, false
	}
	recLen := int(u32(ppd, op+4))
	start := op + 8
	end := start + recLen
	if end > len(ppd) {
		return nil, nil, false
	}
	dir := map[uint32]int{}
	var order []uint32
	p := start
	for p+4 <= end {
		hdr := u32(ppd, p)
		persistID := hdr & 0xFFFFF
		cPersist := hdr >> 20
		p += 4
		for i := uint32(0); i < cPersist; i++ {
			if p+4 > end {
				return dir, order, true
			}
			off := int(u32(ppd, p))
			p += 4
			key := persistID + i
			if _, seen := dir[key]; !seen {
				order = append(order, key)
			}
			dir[key] = off
		}
	}
	return dir, order, true
}

// pptDecrypt reconstructs the decrypted PowerPoint Document stream: it clears
// the encryption markers in the UserEditAtom and PersistDirectoryAtom, zeroes
// the CryptSession10Container, and RC4-decrypts each persist object with its
// persist id as the block number. [MS-PPT] 2.3 / [MS-OFFCRYPTO] 2.3.5.
func pptDecrypt(ei *encInfo, pw, ppd []byte, offsetCurrentEdit int, ue userEditAtom, dir map[uint32]int, order []uint32) ([]byte, error) {
	if ok, err := ei.verify(pw); err != nil || !ok {
		return nil, errWrongPassword(err)
	}
	dec := append([]byte{}, ppd...)

	// UserEditAtom: drop encryptSessionPersistIdRef (recLen -= 4, field zeroed).
	if offsetCurrentEdit+40 <= len(dec) {
		binary.LittleEndian.PutUint32(dec[offsetCurrentEdit+4:], ue.recLen-4)
		binary.LittleEndian.PutUint32(dec[offsetCurrentEdit+36:], 0)
	}
	// PersistDirectoryAtom: first entry cPersist -= 1 (omit CryptSession10Container).
	op := ue.offsetPersistDirectory
	if op+12 <= len(dec) {
		hdr := u32(dec, op+8)
		persistID := hdr & 0xFFFFF
		cPersist := hdr >> 20
		if cPersist > 0 {
			cPersist--
		}
		binary.LittleEndian.PutUint32(dec[op+8:], persistID|(cPersist<<20))
	}

	for i, key := range order {
		off := dir[key]
		if off < 0 || off+8 > len(ppd) {
			continue
		}
		recType := u16(ppd, off+2)
		recLen := int(u32(ppd, off+4))
		if recType == pptCryptSession10 {
			z := off + 8 + recLen
			if z > len(dec) {
				z = len(dec)
			}
			for j := off; j < z; j++ {
				dec[j] = 0
			}
			continue
		}
		if recType == pptUserEditAtom || recType == pptPersistDirectory {
			continue
		}
		// Object length from the next directory entry's offset (reference hack).
		var objEnd int
		if i+1 < len(order) {
			objEnd = dir[order[i+1]]
		} else {
			objEnd = len(ppd)
		}
		objLen := objEnd - off
		if objLen <= 8 || off+objLen > len(ppd) {
			continue
		}
		decObj, err := ei.decryptBlocks(pw, ppd[off:off+objLen], objLen, key)
		if err != nil {
			return nil, err
		}
		copy(dec[off:off+objLen], decObj)
	}
	return dec, nil
}
