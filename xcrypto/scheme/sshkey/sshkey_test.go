package sshkey

import (
	"bytes"
	"encoding/binary"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func load(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseEncrypted(t *testing.T) {
	info, err := Parse(load(t, "enc_ed25519"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.KDF != "bcrypt" {
		t.Errorf("KDF = %q, want bcrypt", info.KDF)
	}
	if info.Cipher != "aes256-ctr" {
		t.Errorf("Cipher = %q, want aes256-ctr", info.Cipher)
	}
	if info.Rounds == 0 || len(info.Salt) == 0 {
		t.Errorf("missing rounds/salt: %d %x", info.Rounds, info.Salt)
	}
}

func TestParsePlainIsNotEncrypted(t *testing.T) {
	if _, err := Parse(load(t, "plain_ed25519")); err != ErrNotEncrypted {
		t.Fatalf("Parse(plain) = %v, want ErrNotEncrypted", err)
	}
}

func TestParseNotAKey(t *testing.T) {
	if _, err := Parse([]byte("hello world")); err != ErrNotSSHKey {
		t.Fatalf("Parse(junk) = %v, want ErrNotSSHKey", err)
	}
}

// TestVerifyAndDecrypt cross-validates against ssh-keygen-produced keys: the
// right passphrase verifies and decrypts to a valid PKCS#8 key, wrong ones fail.
func TestVerifyAndDecrypt(t *testing.T) {
	cases := []struct{ file, pass string }{
		{"enc_ed25519", "correct horse"},
		{"enc_rsa", "Hunter2!"},
	}
	for _, c := range cases {
		pem := load(t, c.file)
		if ok, _ := Verify(pem, []byte(c.pass)); !ok {
			t.Fatalf("%s: correct passphrase did not verify", c.file)
		}
		if ok, _ := Verify(pem, []byte("wrong-"+c.pass)); ok {
			t.Fatalf("%s: wrong passphrase verified", c.file)
		}
		out, err := Decrypt(pem, []byte(c.pass))
		if err != nil {
			t.Fatalf("%s: Decrypt: %v", c.file, err)
		}
		if !bytes.Contains(out, []byte("-----BEGIN PRIVATE KEY-----")) {
			t.Fatalf("%s: decrypted output is not a PKCS#8 PEM:\n%s", c.file, out)
		}
	}
}

// TestParseRejectsOversizeRounds guards the bcrypt-pbkdf rounds cap: the field
// is a uint32 read from the kdfoptions and the derivation is linear in it, so an
// implausible value must be rejected at parse rather than hang. A positive
// control (sane rounds parse fine) keeps the test from passing vacuously.
func TestParseRejectsOversizeRounds(t *testing.T) {
	str := func(b []byte) []byte {
		n := make([]byte, 4)
		binary.BigEndian.PutUint32(n, uint32(len(b)))
		return append(n, b...)
	}
	u32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b
	}
	build := func(rounds uint32) []byte {
		kdfOpts := append(str([]byte("0123456789abcdef")), u32(rounds)...)
		blob := []byte(magic)
		blob = append(blob, str([]byte("aes256-ctr"))...)
		blob = append(blob, str([]byte("bcrypt"))...)
		blob = append(blob, str(kdfOpts)...)
		return pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: blob})
	}
	if _, err := Parse(build(16)); err != nil {
		t.Fatalf("positive control: sane rounds rejected: %v", err)
	}
	if _, err := Parse(build(maxRounds + 1)); err == nil {
		t.Fatal("oversize bcrypt rounds accepted")
	}
}
