package argon2

import (
	"bytes"
	"encoding/hex"
	"testing"

	xargon2 "golang.org/x/crypto/argon2"
)

// TestAgainstXCrypto cross-checks the shared core (H0, block init, compression,
// i/id addressing, finalization) against golang.org/x/crypto/argon2, which is
// the reference for Argon2i (Key) and Argon2id (IDKey). Matching it bit-for-bit
// leaves only the Argon2d addressing to validate separately (TestArgon2dKAT).
func TestAgainstXCrypto(t *testing.T) {
	cases := []struct {
		pw, salt  string
		time, mem uint32
		threads   uint8
		keyLen    uint32
	}{
		{"password", "somesalt", 1, 64, 1, 32},
		{"password", "somesalt", 3, 256, 1, 32},
		{"hunter2", "NaCl-NaCl-16byte", 2, 512, 2, 32},
		{"", "0123456789abcdef", 4, 128, 4, 64},
		{"long passphrase with spaces", "saltsaltsalt", 2, 1024, 2, 40},
	}
	for _, c := range cases {
		pw, salt := []byte(c.pw), []byte(c.salt)
		if got, want := Argon2i(pw, salt, c.time, c.mem, c.threads, c.keyLen),
			xargon2.Key(pw, salt, c.time, c.mem, c.threads, c.keyLen); !bytes.Equal(got, want) {
			t.Errorf("Argon2i(%q,%q,t=%d,m=%d,p=%d) mismatch vs x/crypto\n got %x\nwant %x", c.pw, c.salt, c.time, c.mem, c.threads, got, want)
		}
		if got, want := Argon2id(pw, salt, c.time, c.mem, c.threads, c.keyLen),
			xargon2.IDKey(pw, salt, c.time, c.mem, c.threads, c.keyLen); !bytes.Equal(got, want) {
			t.Errorf("Argon2id(%q,%q,t=%d,m=%d,p=%d) mismatch vs x/crypto\n got %x\nwant %x", c.pw, c.salt, c.time, c.mem, c.threads, got, want)
		}
	}
}

// TestArgon2dKAT checks Argon2d against known-answer vectors produced by the
// reference `argon2` CLI (phc-winner-argon2), version 0x13. Generated with:
//
//	printf '%s' <pw> | argon2 <salt> -d -t <t> -k <memKiB> -p <p> -l <len> -r
func TestArgon2dKAT(t *testing.T) {
	cases := []struct {
		pw, salt  string
		time, mem uint32
		threads   uint8
		keyLen    uint32
		want      string
	}{
		{"password", "somesalt", 1, 64, 1, 32, "063f9e47e2f270b195d3e16245f2f73a0c47244f1703fbc04348a0585bde7c4f"},
		{"password", "somesalt", 3, 256, 1, 32, "0b81c3aa80de399504f6c0de876717d08cd746490e6dc473bf75e01d1c0ff44c"},
		{"hunter2", "NaCl-NaCl-16byte", 2, 512, 2, 32, "6c800f4c6e274482e56bb96fa0c58539dd49d4e0b20293d913a1c582118e3327"},
		{"keepass", "0123456789abcdef", 4, 128, 4, 32, "811ee7046ee7b0be95c6d59ad674bff2d40dbda074d0748b70c06bc814a5b91c"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(Argon2d([]byte(c.pw), []byte(c.salt), c.time, c.mem, c.threads, c.keyLen))
		if got != c.want {
			t.Errorf("Argon2d(%q,%q,t=%d,k=%d,p=%d,l=%d)\n got %s\nwant %s",
				c.pw, c.salt, c.time, c.mem, c.threads, c.keyLen, got, c.want)
		}
	}
}
