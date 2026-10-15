package xcrack

import (
	"bytes"
	"context"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xfileformats/formats/odf"
)

func TestEncryptedODFDecrypt(t *testing.T) {
	password := "office-pw"
	content := bytes.Repeat([]byte("<text:p>secret</text:p>"), 50)
	data, err := odf.BuildEncryptedODF([]byte(password), content, 1000)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.Explicit("nope", password), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	if res.Root.Format != "odf" {
		t.Fatalf("root format = %q, want odf", res.Root.Format)
	}
	var got []byte
	var decrypted bool
	res.Root.Walk(func(n *Node) {
		if n.Path != "" && n.WasEncrypted && n.Status == StatusDecrypted && n.Content != nil {
			decrypted = true
			rc, _ := n.Content.Open()
			got, _ = readAllRC(rc)
		}
	})
	if !decrypted {
		t.Fatalf("no decrypted entry; tree:\n%s", dumpTree(res.Root))
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("decrypted content mismatch (%d vs %d)", len(got), len(content))
	}
}
