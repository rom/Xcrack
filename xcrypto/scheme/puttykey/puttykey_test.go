package puttykey

import (
	"bytes"
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

func TestVerifyV3V2(t *testing.T) {
	for _, f := range []string{"enc_v3.ppk", "enc_v2.ppk"} {
		data := load(t, f)
		info, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: Parse: %v", f, err)
		}
		ok, err := Verify(info, []byte("Hunter2!"))
		if err != nil || !ok {
			t.Fatalf("%s (v%d): correct passphrase failed: ok=%v err=%v", f, info.Version, ok, err)
		}
		for _, bad := range []string{"hunter2!", "Hunter2", "", "nope"} {
			if ok, _ := Verify(info, []byte(bad)); ok {
				t.Fatalf("%s: wrong passphrase %q verified", f, bad)
			}
		}
	}
}

func TestParseJunk(t *testing.T) {
	if _, err := Parse([]byte("not a ppk")); err != ErrNotPPK {
		t.Fatalf("junk = %v, want ErrNotPPK", err)
	}
}

func FuzzParse(f *testing.F) {
	for _, n := range []string{"enc_v3.ppk", "enc_v2.ppk"} {
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

// TestParseRejectsOversizeArgon guards the v3 Argon2 cost caps: Memory (KiB) and
// Passes come straight from the .ppk header, so a crafted value must be refused
// at parse (OOM / hang) rather than reaching argon2. The unmodified key is the
// positive control.
func TestParseRejectsOversizeArgon(t *testing.T) {
	raw := load(t, "enc_v3.ppk")
	if _, err := Parse(raw); err != nil {
		t.Fatalf("positive control: baseline v3 ppk rejected: %v", err)
	}
	bad := bytes.Replace(raw, []byte("Argon2-Memory: 8192"), []byte("Argon2-Memory: 999999999"), 1)
	if bytes.Equal(bad, raw) {
		t.Fatal("could not patch Argon2-Memory in testdata")
	}
	if _, err := Parse(bad); err == nil {
		t.Fatal("oversize Argon2-Memory accepted")
	}
}
