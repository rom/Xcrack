package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"hash/crc32"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/scheme/zipcrypto"
)

// buildMixedZip builds a ZIP with one plaintext entry and one ZipCrypto-encrypted
// entry, so the engine can harvest text from the plain entry to seed a crack of
// the encrypted sibling.
func buildMixedZip(t *testing.T, plainName string, plainBody []byte, encName string, encPw, encBody []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)

	// plain entry
	pw, err := zw.Create(plainName)
	if err != nil {
		t.Fatal(err)
	}
	pw.Write(plainBody)

	// encrypted entry
	crc := crc32.ChecksumIEEE(encBody)
	var comp bytes.Buffer
	fw, _ := flate.NewWriter(&comp, flate.DefaultCompression)
	fw.Write(encBody)
	fw.Close()
	raw := zipcrypto.EncryptRaw(encPw, make([]byte, zipcrypto.HeaderLen-1), byte(crc>>24), comp.Bytes())
	fh := &stdzip.FileHeader{Name: encName, Method: stdzip.Deflate}
	fh.Flags |= 0x1
	fh.CRC32 = crc
	fh.UncompressedSize64 = uint64(len(encBody))
	fh.CompressedSize64 = uint64(len(raw))
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(raw)

	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func childByBase(root *Node, base string) *Node {
	var found *Node
	root.Walk(func(n *Node) {
		if found == nil && lastPathComponent(n.Path) == base {
			found = n
		}
	})
	return found
}

func lastPathComponent(p string) string {
	// mirror candidates.lastComponent for test assertions
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// TestContextHarvestFromSibling: a plaintext readme names the password; with
// ContextCandidates on and NO base candidates, the engine harvests it and cracks
// the encrypted sibling.
func TestContextHarvestFromSibling(t *testing.T) {
	data := buildMixedZip(t,
		"readme.txt", []byte("To open the archive the password is swordfish — keep it safe."),
		"secret.txt", []byte("swordfish"), []byte("top secret payload"))

	// empty base source: the ONLY way to crack is via harvested context.
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit(), Options{ContextCandidates: true, FileConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	sec := childByBase(res.Root, "secret.txt")
	if sec == nil {
		t.Fatal("secret.txt node not found")
	}
	if sec.Status != StatusDecrypted {
		t.Fatalf("secret.txt status = %v, want decrypted (context harvest failed)", sec.Status)
	}
	if sec.Password != "swordfish" {
		t.Errorf("password = %q, want swordfish", sec.Password)
	}
}

// TestContextDisabledByDefault: without ContextCandidates, the same archive stays
// locked (proves harvesting is opt-in and the base source is otherwise empty).
func TestContextDisabledByDefault(t *testing.T) {
	data := buildMixedZip(t,
		"readme.txt", []byte("the password is swordfish"),
		"secret.txt", []byte("swordfish"), []byte("top secret payload"))

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit(), Options{FileConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	sec := childByBase(res.Root, "secret.txt")
	if sec == nil || sec.Status == StatusDecrypted {
		t.Fatalf("secret.txt should stay locked without ContextCandidates, got %v", sec)
	}
}

// TestContextFromName: an entry named after its password is cracked from the
// filename alone, with no base candidates.
func TestContextFromName(t *testing.T) {
	data := buildMixedZip(t,
		"note.txt", []byte("no hint here"),
		"swordfish.txt", []byte("swordfish"), []byte("payload"))

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit(), Options{ContextCandidates: true, FileConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	sec := childByBase(res.Root, "swordfish.txt")
	if sec == nil || sec.Status != StatusDecrypted || sec.Password != "swordfish" {
		t.Fatalf("name-derived crack failed: %+v", sec)
	}
}

// TestFastRejectGatesKDF: a FastReject that rejects the only working password
// prevents the crack; one that permits it allows it. Proves the hook gates Verify.
func TestFastRejectReject(t *testing.T) {
	data := buildMixedZip(t,
		"note.txt", []byte("irrelevant"),
		"secret.txt", []byte("swordfish"), []byte("payload"))

	rejectAll := func(path string, cand []byte) bool { return true }
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("swordfish"), Options{FastReject: rejectAll, FileConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	sec := childByBase(res.Root, "secret.txt")
	if sec == nil || sec.Status == StatusDecrypted {
		t.Fatalf("FastReject(true) should block the crack, got %v", sec)
	}
}

func TestFastRejectAllow(t *testing.T) {
	data := buildMixedZip(t,
		"note.txt", []byte("irrelevant"),
		"secret.txt", []byte("swordfish"), []byte("payload"))

	// Reject anything that is not all-lowercase-letters; "swordfish" survives.
	reject := func(path string, cand []byte) bool {
		for _, c := range cand {
			if c < 'a' || c > 'z' {
				return true
			}
		}
		return false
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("DECOY1", "swordfish"), Options{FastReject: reject, FileConcurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	sec := childByBase(res.Root, "secret.txt")
	if sec == nil || sec.Status != StatusDecrypted || sec.Password != "swordfish" {
		t.Fatalf("FastReject permitting the password should allow the crack, got %+v", sec)
	}
}
