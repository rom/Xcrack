package iwork

import (
	stdzip "archive/zip"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/rom/xfileformats"
)

// pagesVerifier is the real .iwpv2 from a Pages 14.5 document (passphrase
// "Password"); see xcrypto/scheme/iwork/testdata/ATTRIBUTION.md.
const pagesVerifierHex = "02000100a08601005245a6a24b06fc9b5ae9e07ffebf5dffd67c47177cfdc6f7befd22f7eb77076ab1e37c05001717b4fc2f15ffff68f1cb3621bd7a33295ef3c462442e1430de4d6ea39973af558915c0301a8b27b92a6d623571ad90cf97cead1e1fbebfbad375"

func verifier(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString(pagesVerifierHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// zipOf builds a ZIP archive from name->content members (stored).
func zipOf(t *testing.T, members map[string][]byte) []byte {
	t.Helper()
	b, err := zipOfErr(members)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// zipOfRaw is zipOf without a *testing.T (for fuzz seeds); best-effort.
func zipOfRaw(members map[string][]byte) []byte {
	b, _ := zipOfErr(members)
	return b
}

func zipOfErr(members map[string][]byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := stdzip.NewWriter(&buf)
	for name, body := range members {
		w, err := zw.Create(name)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func TestDetect(t *testing.T) {
	f := New()
	if c, ok := f.Detect([]byte("PK\x03\x04and more")); !ok || c <= 0.9 {
		t.Fatalf("zip LFH: conf=%v ok=%v, want >0.9 (outrank generic zip)", c, ok)
	}
	if _, ok := f.Detect([]byte("not a zip")); ok {
		t.Fatal("non-zip detected as iWork")
	}
}

func TestProbeEncrypted(t *testing.T) {
	data := zipOf(t, map[string][]byte{
		".iwpv2":             verifier(t),
		"Index/Document.iwa": []byte("opaque"),
		".iwph":              []byte("Password"),
	})
	f := New()
	ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if ch.Scheme != "iwork" {
		t.Fatalf("scheme = %q", ch.Scheme)
	}
	ok, key, err := f.Verify(ch, []byte("Password"))
	if err != nil || !ok || key == nil {
		t.Fatalf("Verify(correct): ok=%v key=%v err=%v", ok, key, err)
	}
	if ok, _, _ := f.Verify(ch, []byte("wrong")); ok {
		t.Fatal("Verify(wrong) accepted")
	}
	// Decrypt returns the archive bytes unchanged.
	r, err := f.Decrypt(bytes.NewReader(data), int64(len(data)), ch, key)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	got, _ := io.ReadAll(r)
	if !bytes.Equal(got, data) {
		t.Fatal("Decrypt did not return the archive unchanged")
	}
}

func TestProbeDeclines(t *testing.T) {
	f := New()
	// An iWork document with no passphrase -> ErrNotEncrypted.
	noPw := zipOf(t, map[string][]byte{"Index/Document.iwa": []byte("x")})
	if _, err := f.Probe(bytes.NewReader(noPw), int64(len(noPw))); !errors.Is(err, xfileformats.ErrNotEncrypted) {
		t.Fatalf("unencrypted iWork: err=%v, want ErrNotEncrypted", err)
	}
	// A plain non-iWork zip -> ErrUnknownFormat (engine falls back to zip).
	plain := zipOf(t, map[string][]byte{"hello.txt": []byte("hi")})
	if _, err := f.Probe(bytes.NewReader(plain), int64(len(plain))); !errors.Is(err, xfileformats.ErrUnknownFormat) {
		t.Fatalf("plain zip: err=%v, want ErrUnknownFormat", err)
	}
	// Not a zip at all -> ErrUnknownFormat.
	junk := []byte("PK\x03\x04 but truncated garbage not a real zip")
	if _, err := f.Probe(bytes.NewReader(junk), int64(len(junk))); err == nil {
		t.Fatal("garbage accepted")
	}
}
