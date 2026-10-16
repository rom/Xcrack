package keepass

import (
	"bytes"
	"os"
	"testing"
)

func TestKeePassFormat(t *testing.T) {
	data, err := os.ReadFile("testdata/pykeepass-argon2d.kdbx")
	if err != nil {
		t.Skip("fixture missing")
	}
	f := New()
	if conf, ok := f.Detect(data[:8]); !ok || conf < 0.9 {
		t.Fatalf("Detect: ok=%v conf=%v", ok, conf)
	}
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ch.Scheme != "keepass-kdbx4-argon2d" {
		t.Fatalf("scheme = %q", ch.Scheme)
	}
	ok, key, err := f.Verify(ch, []byte("opensesame"))
	if err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	if string(key) != "opensesame" {
		t.Fatalf("recovered key = %q", key)
	}
	if bad, _, _ := f.Verify(ch, []byte("wrong")); bad {
		t.Fatal("Verify(wrong) = true")
	}
}

func TestKeePassDetectRejectsOther(t *testing.T) {
	if _, ok := New().Detect([]byte("not-kdbx!")); ok {
		t.Error("must not detect non-KDBX input")
	}
}
