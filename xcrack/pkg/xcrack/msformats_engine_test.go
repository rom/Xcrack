package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats/formats/ooxml"
)

// TestEncryptedOfficeFamilyDecrypts proves that an encrypted Office-family file
// using the standard agile Office encryption decrypts through the shared ooxml
// path regardless of which application produced it — here a Visio-shaped
// package (`visio/document.xml`). The same holds for Publisher/Project and any
// other agile-encrypted Office file: the engine keys on the CFB EncryptionInfo
// container, not the file extension.
func TestEncryptedOfficeFamilyDecrypts(t *testing.T) {
	var zb bytes.Buffer
	zw := stdzip.NewWriter(&zb)
	w, _ := zw.Create("visio/document.xml")
	w.Write([]byte("<VisioDocument><Pages/></VisioDocument>"))
	ct, _ := zw.Create("[Content_Types].xml")
	ct.Write([]byte(`<?xml version="1.0"?><Types/>`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	const pw = "V!sio-2026"
	data, err := ooxml.BuildEncryptedAgile([]byte(pw), zb.Bytes(), 100)
	if err != nil {
		t.Fatal(err)
	}

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong", pw), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Root.Status != StatusDecrypted || res.Root.Password != pw {
		t.Fatalf("root not decrypted: status=%v pw=%q", res.Root.Status, res.Root.Password)
	}
	// The decrypted package is decomposed; the Visio part must surface.
	found := false
	res.Root.Walk(func(n *Node) {
		if n.Path != "" && bytes.Contains([]byte(n.Path), []byte("visio/document.xml")) {
			found = true
		}
	})
	if !found {
		t.Fatalf("decrypted Visio part not found; tree:\n%s", dumpTree(res.Root))
	}
}

// TestForceSQLCipher exercises the --as force-format path: ForceRegistry gives a
// registry with only the (magic-less) SQLCipher format, and the engine recovers
// the passphrase of the scheme's own test database.
func TestForceSQLCipher(t *testing.T) {
	data, err := os.ReadFile("../../../xcrypto/scheme/sqlcipher/testdata/v4.db")
	if err != nil {
		t.Skip("sqlcipher fixture not available:", err)
	}
	reg, ok := ForceRegistry("sqlcipher")
	if !ok {
		t.Fatal("ForceRegistry(sqlcipher) not ok")
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("wrong", "Hunter2!"), Options{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	if res.Root.Format != "sqlcipher" {
		t.Fatalf("format = %q, want sqlcipher", res.Root.Format)
	}
	if res.Root.Status != StatusDecrypted || res.Root.Password != "Hunter2!" {
		t.Fatalf("status=%v pw=%q, want decrypted/Hunter2!", res.Root.Status, res.Root.Password)
	}
	if _, ok := ForceRegistry("nope"); ok {
		t.Error("ForceRegistry(nope) should be not-ok")
	}
}
