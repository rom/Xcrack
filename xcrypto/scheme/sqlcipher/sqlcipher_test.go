package sqlcipher

import (
	"os"
	"path/filepath"
	"testing"
)

func load(t *testing.T, n string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", n))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVerifyV4V3(t *testing.T) {
	cases := []struct {
		file string
		prof Params
	}{
		{"v4.db", DefaultV4()},
		{"v3.db", DefaultV3()},
	}
	for _, c := range cases {
		data := load(t, c.file)
		ok, err := Verify(data, []byte("Hunter2!"), c.prof)
		if err != nil || !ok {
			t.Fatalf("%s: correct key failed: ok=%v err=%v", c.file, ok, err)
		}
		for _, bad := range []string{"hunter2!", "Hunter2", "", "nope"} {
			if ok, _ := Verify(data, []byte(bad), c.prof); ok {
				t.Fatalf("%s: wrong key %q verified", c.file, bad)
			}
		}
	}
}

// TestVerifyAny finds the right profile without being told the version.
func TestVerifyAny(t *testing.T) {
	for _, f := range []string{"v4.db", "v3.db"} {
		p, ok := VerifyAny(load(t, f), []byte("Hunter2!"), DefaultProfiles())
		if !ok {
			t.Fatalf("%s: VerifyAny failed", f)
		}
		t.Logf("%s matched profile %s", f, p.Name)
	}
}

func FuzzVerify(f *testing.F) {
	if b, e := os.ReadFile(filepath.Join("testdata", "v4.db")); e == nil {
		f.Add(b)
	}
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		Verify(data, []byte("x"), DefaultV4())
		Verify(data, []byte("x"), DefaultV3())
	})
}
