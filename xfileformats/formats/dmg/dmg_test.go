package dmg

import (
	"bytes"
	"testing"
)

// A short v1 ($dmg$1) line from John the Ripper's authoritative vectors,
// prefixed with a filename as dmg2john emits it. Password: "vilefault".
const v1Line = "img.dmg:$dmg$1*20*f615ec6c463799eccc6a2dfbedf12c6bdc422a2a*56*" +
	"a595f4a81a490e7aa6378034661da57a424f922c971d3db3f856f8d54b0784bcc5d7182905c4237153c5d250b8aee1d26410b1dca7b1cb73*48*" +
	"74a060efbaf2c79d5523219d8162c425befbb2094fb46e7ffaedc7cd4f192e6f0c47d8aa91e0a3201346725d3ddadfff"

func TestDetectAndVerify(t *testing.T) {
	f := New()
	if conf, ok := f.Detect([]byte(v1Line)); !ok || conf <= 0 {
		t.Fatalf("Detect = (%v,%v), want detected", conf, ok)
	}
	data := []byte(v1Line + "\n")
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ch.Scheme != "dmg-v1" {
		t.Errorf("scheme = %q, want dmg-v1", ch.Scheme)
	}
	ok, key, err := f.Verify(ch, []byte("vilefault"))
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = (%v,%v)", ok, err)
	}
	if string(key) != "vilefault" {
		t.Errorf("recovered key = %q", key)
	}
	if ok, _, _ := f.Verify(ch, []byte("wrong")); ok {
		t.Error("Verify(wrong) = true, want false")
	}
}

func TestProbeNonDMG(t *testing.T) {
	f := New()
	if _, ok := f.Detect([]byte("PK\x03\x04 not a dmg")); ok {
		t.Error("Detect should not claim a non-dmg buffer")
	}
	// A buffer that is detected (contains the marker) but does not parse must
	// report a non-fatal status, not a crash.
	data := []byte("x:$dmg$zzz")
	if _, err := f.Probe(bytes.NewReader(data), int64(len(data))); err == nil {
		t.Error("Probe of a malformed $dmg$ line should error")
	}
}

func TestProbeFindsLineAmongOthers(t *testing.T) {
	f := New()
	data := []byte("# a comment\nnoise line\n" + v1Line + "\nmore\n")
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ok, _, _ := f.Verify(ch, []byte("vilefault")); !ok {
		t.Error("expected the embedded $dmg$ line to be found and verified")
	}
}
