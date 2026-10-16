package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// pagesVerifierHex is the real .iwpv2 from a Pages 14.5 document (passphrase
// "Password"); see xcrypto/scheme/iwork/testdata/ATTRIBUTION.md.
const pagesVerifierHex = "02000100a08601005245a6a24b06fc9b5ae9e07ffebf5dffd67c47177cfdc6f7befd22f7eb77076ab1e37c05001717b4fc2f15ffff68f1cb3621bd7a33295ef3c462442e1430de4d6ea39973af558915c0301a8b27b92a6d623571ad90cf97cead1e1fbebfbad375"

// buildIWorkDoc builds a minimal encrypted iWork archive wrapping the real
// verifier, so the engine exercises the whole detect→probe→verify path.
func buildIWorkDoc(t *testing.T) []byte {
	t.Helper()
	verifier, err := hex.DecodeString(pagesVerifierHex)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := stdzip.NewWriter(&buf)
	for name, body := range map[string][]byte{
		".iwpv2":             verifier,
		".iwph":              []byte("Password"),
		"Index/Document.iwa": []byte("opaque encrypted protobuf"),
	} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(body)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestEngineCracksIWork proves the engine detects an encrypted iWork document,
// recovers its passphrase from the candidate list, and reports it — and does NOT
// mis-handle it as a generic zip.
func TestEngineCracksIWork(t *testing.T) {
	data := buildIWorkDoc(t)
	src := candidates.Explicit("decoy1", "letmein", "Password", "decoy2")

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)), src, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	n := res.Root
	if n.Format != "iwork" {
		t.Fatalf("format = %q, want iwork", n.Format)
	}
	if n.Status != StatusDecrypted {
		t.Fatalf("status = %v, want decrypted", n.Status)
	}
	if n.Password != "Password" {
		t.Fatalf("password = %q, want %q", n.Password, "Password")
	}
}

// TestEngineIWorkWrongList leaves it locked when the passphrase is absent, and
// must not crash or falsely claim success.
func TestEngineIWorkWrongList(t *testing.T) {
	data := buildIWorkDoc(t)
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("nope", "wrong"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Root.Status == StatusDecrypted {
		t.Fatal("falsely reported decrypted with wrong candidates")
	}
	if res.Root.Format != "iwork" {
		t.Fatalf("format = %q, want iwork", res.Root.Format)
	}
}

// TestEnginePlainZipStillWorks guards against the iwork format hijacking generic
// zips: a plain (non-iWork) zip must still be handled by the zip format.
func TestEnginePlainZipStillWorks(t *testing.T) {
	var buf bytes.Buffer
	zw := stdzip.NewWriter(&buf)
	w, _ := zw.Create("readme.txt")
	w.Write([]byte("hello world"))
	zw.Close()
	data := buf.Bytes()

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)), candidates.Explicit(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()
	if res.Root.Format != "zip" {
		t.Fatalf("plain zip format = %q, want zip (iwork must decline)", res.Root.Format)
	}
}
