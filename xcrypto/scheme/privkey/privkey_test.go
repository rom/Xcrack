package privkey

import (
	"bytes"
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

const pass = "Hunter2!"

// TestVerifyDecryptAllForms cross-validates against OpenSSL-produced keys: legacy
// DEK-Info PEM (RSA, EC) and PKCS#8 PBES2 (PBKDF2 and scrypt). Correct passphrase
// verifies and decrypts to a well-formed key; wrong ones fail.
func TestVerifyDecryptAllForms(t *testing.T) {
	for _, f := range []string{"trad_rsa.pem", "legacy_ec.pem", "pkcs8_aes.pem", "pkcs8_scrypt.pem"} {
		data := load(t, f)
		if _, err := Parse(data); err != nil {
			t.Fatalf("%s: Parse: %v", f, err)
		}
		if ok, _ := Verify(data, []byte(pass)); !ok {
			t.Fatalf("%s: correct passphrase did not verify", f)
		}
		if ok, _ := Verify(data, []byte("wrong")); ok {
			t.Fatalf("%s: wrong passphrase verified", f)
		}
		out, err := Decrypt(data, []byte(pass))
		if err != nil {
			t.Fatalf("%s: Decrypt: %v", f, err)
		}
		if !bytes.Contains(out, []byte("PRIVATE KEY")) {
			t.Fatalf("%s: decrypted output not a PEM key:\n%s", f, out)
		}
	}
}

func TestParseClassification(t *testing.T) {
	if info, err := Parse(load(t, "pkcs8_aes.pem")); err != nil || info.Mode != ModePKCS8 {
		t.Fatalf("pkcs8 classify: %v %+v", err, info)
	}
	if info, err := Parse(load(t, "trad_rsa.pem")); err != nil || info.Mode != ModeLegacy {
		t.Fatalf("legacy classify: %v %+v", err, info)
	}
	if info, err := Parse(load(t, "legacy_ec.pem")); err != nil || info.Mode != ModeLegacy {
		t.Fatalf("legacy EC classify: %v %+v", err, info)
	}
	if _, err := Parse([]byte("not a key")); err != ErrNotKey {
		t.Fatalf("junk = %v, want ErrNotKey", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, n := range []string{"pkcs8_aes.pem", "legacy_rsa.pem"} {
		if b, err := os.ReadFile(filepath.Join("testdata", n)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if info, err := Parse(data); err == nil && info != nil {
			Verify(data, []byte("x"))
		}
	})
}
