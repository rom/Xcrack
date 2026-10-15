package officebinary

// XOR obfuscation ("Method 1"), the weakest legacy Office scheme. The password
// yields a 16-byte XOR key array and a 16-bit verifier. Encrypted bytes are
// XORed with a rotating element of the key array and rotated right by 5.
// [MS-OFFCRYPTO] 2.3.7.

var xorPadArray = [15]byte{
	0xBB, 0xFF, 0xFF, 0xBA, 0xFF, 0xFF, 0xB9, 0x80,
	0x00, 0xBE, 0x0F, 0x00, 0xBF, 0x0F, 0x00,
}

var xorInitialCode = [15]uint16{
	0xE1F0, 0x1D0F, 0xCC9C, 0x84C0, 0x110C, 0x0E10, 0xF1CE, 0x313E,
	0x1872, 0xE139, 0xD40F, 0x84F9, 0x280C, 0xA96A, 0x4EC3,
}

var xorMatrix = [105]uint16{
	0xAEFC, 0x4DD9, 0x9BB2, 0x2745, 0x4E8A, 0x9D14, 0x2A09, 0x7B61,
	0xF6C2, 0xFDA5, 0xEB6B, 0xC6F7, 0x9DCF, 0x2BBF, 0x4563, 0x8AC6,
	0x05AD, 0x0B5A, 0x16B4, 0x2D68, 0x5AD0, 0x0375, 0x06EA, 0x0DD4,
	0x1BA8, 0x3750, 0x6EA0, 0xDD40, 0xD849, 0xA0B3, 0x5147, 0xA28E,
	0x553D, 0xAA7A, 0x44D5, 0x6F45, 0xDE8A, 0xAD35, 0x4A4B, 0x9496,
	0x390D, 0x721A, 0xEB23, 0xC667, 0x9CEF, 0x29FF, 0x53FE, 0xA7FC,
	0x5FD9, 0x47D3, 0x8FA6, 0x0F6D, 0x1EDA, 0x3DB4, 0x7B68, 0xF6D0,
	0xB861, 0x60E3, 0xC1C6, 0x93AD, 0x377B, 0x6EF6, 0xDDEC, 0x45A0,
	0x8B40, 0x06A1, 0x0D42, 0x1A84, 0x3508, 0x6A10, 0xAA51, 0x4483,
	0x8906, 0x022D, 0x045A, 0x08B4, 0x1168, 0x76B4, 0xED68, 0xCAF1,
	0x85C3, 0x1BA7, 0x374E, 0x6E9C, 0x3730, 0x6E60, 0xDCC0, 0xA9A1,
	0x4363, 0x86C6, 0x1DAD, 0x3331, 0x6662, 0xCCC4, 0x89A9, 0x0373,
	0x06E6, 0x0DCC, 0x1021, 0x2042, 0x4084, 0x8108, 0x1231, 0x2462,
	0x48C4,
}

func ror8(n byte, rot uint) byte {
	return byte((uint(n)>>rot | uint(n)<<(8-rot)) & 0xFF)
}

func rol8(n byte, rot uint) byte {
	return byte((uint(n)<<rot | uint(n)>>(8-rot)) & 0xFF)
}

func xorRor(b1, b2 byte) byte {
	return ror8(b1^b2, 1)
}

// VerifyXOR reports whether password matches the 16-bit XOR password verifier.
// [MS-OFFCRYPTO] 2.3.7.4 (CreatePasswordVerifier_Method1).
func VerifyXOR(password []byte, verificationBytes uint16) bool {
	var verifier uint16
	arr := make([]int, 0, len(password)+1)
	arr = append(arr, len(password))
	for _, b := range password {
		arr = append(arr, int(b))
	}
	// Iterate in reverse.
	for i := len(arr) - 1; i >= 0; i-- {
		pb := uint16(arr[i])
		var i1 uint16
		if verifier&0x4000 != 0 {
			i1 = 1
		}
		i2 := (verifier * 2) & 0x7FFF
		i3 := i1 ^ i2
		verifier = i3 ^ pb
	}
	return (verifier ^ 0xCE4B) == verificationBytes
}

func createXORKeyMethod1(password []byte) uint16 {
	xorKey := xorInitialCode[len(password)-1]
	current := 0x68
	// data = reversed(password)
	for i := len(password) - 1; i >= 0; i-- {
		ch := password[i]
		for j := 0; j < 7; j++ {
			if ch&0x40 != 0 {
				xorKey ^= xorMatrix[current]
			}
			ch = byte((uint(ch) << 1) & 0xFF)
			current--
		}
	}
	return xorKey
}

// createXORArrayMethod1 derives the 16-byte XOR key array. password length must
// be 1..15. [MS-OFFCRYPTO] 2.3.7.2 (CreateXorArray_Method1).
func createXORArrayMethod1(password []byte) [16]byte {
	xorKey := createXORKeyMethod1(password)
	var arr [16]byte
	index := len(password)
	if index%2 == 1 {
		temp := byte((xorKey & 0xFF00) >> 8)
		arr[index] = xorRor(xorPadArray[0], temp)
		index--
		temp = byte(xorKey & 0x00FF)
		arr[index] = xorRor(password[len(password)-1], temp)
	}
	for index > 0 {
		index--
		temp := byte((xorKey & 0xFF00) >> 8)
		arr[index] = xorRor(password[index], temp)
		index--
		temp = byte(xorKey & 0x00FF)
		arr[index] = xorRor(password[index], temp)
	}
	index = 15
	padIndex := 15 - len(password)
	for padIndex > 0 {
		temp := byte((xorKey & 0xFF00) >> 8)
		arr[index] = xorRor(xorPadArray[padIndex], temp)
		index--
		padIndex--
		temp = byte(xorKey & 0x00FF)
		arr[index] = xorRor(xorPadArray[padIndex], temp)
		index--
		padIndex--
	}
	return arr
}

// XORKeyArray exposes the derived 16-byte key array (for testing / reporting).
func XORKeyArray(password []byte) ([16]byte, bool) {
	if len(password) < 1 || len(password) > 15 {
		return [16]byte{}, false
	}
	return createXORArrayMethod1(password), true
}

// DecryptXORMethod1 decrypts an XOR-obfuscated byte run. plain is a per-byte
// map of the logical stream: a value in 0..255 is a literal (unencrypted) byte,
// -1 marks an encrypted byte, and -2 marks an encrypted byte that also shifts
// the key-array index by 4 at its run start (used for Excel's lbPlyPos-adjacent
// data). cipher holds the raw stream bytes at the same positions; literal
// positions are ignored. The returned slice has len(plain). [MS-OFFCRYPTO]
// 2.3.7.3 (DecryptData_Method1).
func DecryptXORMethod1(password []byte, cipher []byte, plain []int) ([]byte, bool) {
	if len(password) < 1 || len(password) > 15 || len(cipher) != len(plain) {
		return nil, false
	}
	arr := createXORArrayMethod1(password)
	out := make([]byte, 0, len(plain))
	di := 0
	for di < len(plain) {
		count := 1
		if plain[di] == -1 || plain[di] == -2 {
			for j := di + 1; j < len(plain); j++ {
				if plain[j] >= 0 {
					break
				}
				count++
			}
			var xi int
			if plain[di] == -2 {
				xi = (di + count + 4) % 16
			} else {
				xi = (di + count) % 16
			}
			for item := 0; item < count; item++ {
				tr := cipher[di+item] ^ arr[xi]
				tr = ror8(tr, 5)
				out = append(out, tr)
				xi = (xi + 1) % 16
			}
		} else {
			out = append(out, byte(plain[di]))
		}
		di += count
	}
	return out, true
}

// EncryptXORMethod1 is the inverse of DecryptXORMethod1: it produces the
// obfuscated stream from plaintext and the same per-byte plain layout. It
// exists so the decrypt path can be round-trip tested (no production use).
func EncryptXORMethod1(password []byte, plaintext []byte, plain []int) ([]byte, bool) {
	if len(password) < 1 || len(password) > 15 || len(plaintext) != len(plain) {
		return nil, false
	}
	arr := createXORArrayMethod1(password)
	out := make([]byte, 0, len(plain))
	di := 0
	for di < len(plain) {
		count := 1
		if plain[di] == -1 || plain[di] == -2 {
			for j := di + 1; j < len(plain); j++ {
				if plain[j] >= 0 {
					break
				}
				count++
			}
			var xi int
			if plain[di] == -2 {
				xi = (di + count + 4) % 16
			} else {
				xi = (di + count) % 16
			}
			for item := 0; item < count; item++ {
				out = append(out, rol8(plaintext[di+item], 5)^arr[xi])
				xi = (xi + 1) % 16
			}
		} else {
			out = append(out, byte(plain[di]))
		}
		di += count
	}
	return out, true
}
