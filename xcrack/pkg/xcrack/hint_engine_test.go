package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"hash/crc32"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/pattern"
	"github.com/rom/xcrypto/scheme/zipcrypto"
)

// TestHintLiteralIWork cracks an iWork document from its embedded `.iwph` hint
// alone — no candidate list — because the hint IS the passphrase.
func TestHintLiteralIWork(t *testing.T) {
	verifier, err := hex.DecodeString(pagesVerifierHex) // passphrase "Password"
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := stdzip.NewWriter(&buf)
	for name, body := range map[string][]byte{
		".iwpv2":             verifier,
		".iwph":              []byte("Password"), // the hint member
		"Index/Document.iwa": []byte("opaque"),
	} {
		w, _ := zw.Create(name)
		w.Write(body)
	}
	zw.Close()
	data := buf.Bytes()

	// No candidates at all; only the hint is enabled.
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit(), Options{HintCandidates: true})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Root.Status != StatusDecrypted || res.Root.Password != "Password" {
		t.Fatalf("hint-only crack: status=%v pw=%q, want decrypted/Password", res.Root.Status, res.Root.Password)
	}

	// With the hint disabled (default), the same file stays locked.
	res2, _ := Process(context.Background(), bytes.NewReader(data), int64(len(data)), candidates.Explicit(), Options{})
	defer res2.Close()
	if res2.Root.Status == StatusDecrypted {
		t.Fatal("decrypted without the hint enabled and no candidates")
	}
}

// TestHintRulesZipComment cracks a ZipCrypto entry whose comment is a hint that
// only yields the password after a rule (capitalize + append digits).
func TestHintRulesZipComment(t *testing.T) {
	const pw = "Sesame99"
	content := []byte("secret contents")
	crc := crc32.ChecksumIEEE(content)
	raw := zipcrypto.EncryptRaw([]byte(pw), make([]byte, zipcrypto.HeaderLen-1), byte(crc>>24), content)

	var buf bytes.Buffer
	zw := stdzip.NewWriter(&buf)
	fh := &stdzip.FileHeader{Name: "secret.txt", Method: stdzip.Store, Comment: "sesame"} // hint
	fh.Flags |= 0x1
	fh.CRC32 = crc
	fh.UncompressedSize64 = uint64(len(content))
	fh.CompressedSize64 = uint64(len(raw))
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(raw)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()

	// Rule: capitalize, then append "99" -> "sesame" becomes "Sesame99".
	rs, err := pattern.CompileRules([]string{"c $9 $9"})
	if err != nil {
		t.Fatal(err)
	}
	hintRules := func(base string) []string {
		var out []string
		for _, v := range rs.Apply([]byte(base)) {
			out = append(out, string(v))
		}
		return out
	}

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit(), Options{HintCandidates: true, HintRules: hintRules})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if len(res.Root.Children) != 1 {
		t.Fatalf("got %d children, want 1", len(res.Root.Children))
	}
	ch := res.Root.Children[0]
	if ch.Status != StatusDecrypted || ch.Password != pw {
		t.Fatalf("hint+rule crack: status=%v pw=%q, want decrypted/%s", ch.Status, ch.Password, pw)
	}
}
