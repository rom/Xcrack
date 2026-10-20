package privkey

import (
	"bytes"
	"encoding/asn1"
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

// TestParsePBES2RejectsOversizeCost guards the PBES2 cost caps: a PKCS#8 header
// can set the PBKDF2 iteration count and the scrypt N/r/p freely, so an
// out-of-range value must be refused at parse rather than hang / OOM. Builds the
// minimal ASN.1 parsePBES2 consumes; a sane value is the positive control, so a
// crafting error can't make the test pass vacuously.
func TestParsePBES2RejectsOversizeCost(t *testing.T) {
	mustMarshal := func(v any) []byte {
		b, err := asn1.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return b
	}
	mk := func(kdf algorithmIdentifier) encryptedPrivateKeyInfo {
		iv := mustMarshal(make([]byte, 16)) // OCTET STRING IV
		enc := algorithmIdentifier{Algorithm: oidAES256CBC, Params: asn1.RawValue{FullBytes: iv}}
		pb := mustMarshal(pbes2Params{KDF: kdf, EncScheme: enc})
		return encryptedPrivateKeyInfo{
			Algo:          algorithmIdentifier{Algorithm: oidPBES2, Params: asn1.RawValue{FullBytes: pb}},
			EncryptedData: make([]byte, 16),
		}
	}
	pbkdf2KDF := func(iter int) algorithmIdentifier {
		kp := mustMarshal(struct { // minimal PBKDF2-params: salt + iter only
			Salt []byte
			Iter int
		}{make([]byte, 8), iter})
		return algorithmIdentifier{Algorithm: oidPBKDF2, Params: asn1.RawValue{FullBytes: kp}}
	}
	scryptKDF := func(n int) algorithmIdentifier {
		sp := mustMarshal(struct {
			Salt    []byte
			N, R, P int
		}{make([]byte, 8), n, 8, 1})
		return algorithmIdentifier{Algorithm: oidScrypt, Params: asn1.RawValue{FullBytes: sp}}
	}
	check := func(name string, epki encryptedPrivateKeyInfo, wantErr bool) {
		_, _, _, _, _, _, _, err := parsePBES2(epki)
		if wantErr && err == nil {
			t.Fatalf("%s: accepted out-of-range cost", name)
		}
		if !wantErr && err != nil {
			t.Fatalf("%s: positive control rejected: %v", name, err)
		}
	}
	check("pbkdf2 sane", mk(pbkdf2KDF(1000)), false)
	check("pbkdf2 huge", mk(pbkdf2KDF(maxPBKDF2Iter+1)), true)
	check("scrypt sane", mk(scryptKDF(1<<10)), false)
	check("scrypt huge N", mk(scryptKDF(1<<25)), true)
}
