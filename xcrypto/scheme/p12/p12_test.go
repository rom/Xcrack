package p12

import (
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
