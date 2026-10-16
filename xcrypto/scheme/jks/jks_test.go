package jks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJKSVerify(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "test.jks"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !Verify(info.Raw, []byte("Hunter2!")) {
		t.Fatal("correct store password did not verify")
	}
	for _, bad := range []string{"hunter2!", "Hunter2", "", "Hunter2!!"} {
		if Verify(info.Raw, []byte(bad)) {
			t.Fatalf("wrong password %q verified", bad)
		}
	}
}

func TestJKSParseJunk(t *testing.T) {
	if _, err := Parse([]byte("not a keystore!!!!!!!!!!!!!!!!!!!!")); err != ErrNotJKS {
		t.Fatalf("junk = %v, want ErrNotJKS", err)
	}
}

func FuzzVerify(f *testing.F) {
	if b, err := os.ReadFile(filepath.Join("testdata", "test.jks")); err == nil {
		f.Add(b)
	}
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		if info, err := Parse(data); err == nil {
			Verify(info.Raw, []byte("x"))
		}
	})
}
