package p12

import (
	"encoding/asn1"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBothForms(t *testing.T) {
	for _, f := range []string{"test.p12", "test_legacy.p12"} {
		data, err := os.ReadFile(filepath.Join("testdata", f))
		if err != nil {
			t.Fatal(err)
		}
		info, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: Parse: %v", f, err)
		}
		if !Verify(info, []byte("Hunter2!")) {
			t.Fatalf("%s (%s): correct password did not verify", f, info.hashName)
		}
		for _, bad := range []string{"hunter2!", "Hunter2", "", "nope"} {
			if Verify(info, []byte(bad)) {
				t.Fatalf("%s: wrong password %q verified", f, bad)
			}
		}
	}
}

func TestParseJunk(t *testing.T) {
	if _, err := Parse([]byte("not der")); err != ErrNotPFX {
		t.Fatalf("junk = %v, want ErrNotPFX", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, n := range []string{"test.p12", "test_legacy.p12"} {
		if b, err := os.ReadFile(filepath.Join("testdata", n)); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if info, err := Parse(data); err == nil {
			Verify(info, []byte("x"))
		}
	})
}

// TestParseRejectsOversizeMacIterations guards the MacData iteration cap: the
// count comes from the PFX (an ASN.1 INTEGER), and the KDF spin loop runs that
// many hashes, so an out-of-range value must be refused at parse. Builds a
// minimal PFX reaching the iter check; a sane count is the positive control.
func TestParseRejectsOversizeMacIterations(t *testing.T) {
	build := func(iter int) []byte {
		inner, _ := asn1.Marshal([]byte("safe-contents")) // OCTET STRING the MAC covers
		p := pfx{
			Version: 3,
			AuthSafe: contentInfo{
				ContentType: oidSHA1, // any OID; not validated
				Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner},
			},
			MacData: macData{
				Mac:        digestInfo{Algorithm: algorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, Digest: []byte{1, 2, 3, 4}},
				MacSalt:    []byte("salt"),
				Iterations: iter,
			},
		}
		b, err := asn1.Marshal(p)
		if err != nil {
			t.Fatalf("marshal pfx: %v", err)
		}
		return b
	}
	if _, err := Parse(build(2048)); err != nil {
		t.Fatalf("positive control: sane iteration count rejected: %v", err)
	}
	if _, err := Parse(build(maxMacIterations + 1)); err != ErrNotPFX {
		t.Fatalf("oversize MacData iterations: got err=%v, want ErrNotPFX", err)
	}
}
