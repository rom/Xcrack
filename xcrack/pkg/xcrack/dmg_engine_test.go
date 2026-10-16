package xcrack

import (
	"bytes"
	"context"
	"testing"

	"github.com/rom/xcrypto/candidates"
)

// TestDMGHashLine runs a dmg2john $dmg$ line through the full engine: the dmg
// format detects it, the password search recovers "vilefault", and the node is
// marked decrypted. This is the end-to-end path a `dmg2john image.dmg | xcrack`
// workflow takes. The vector is one of John the Ripper's authoritative tests.
func TestDMGHashLine(t *testing.T) {
	line := "img.dmg:$dmg$1*20*f615ec6c463799eccc6a2dfbedf12c6bdc422a2a*56*" +
		"a595f4a81a490e7aa6378034661da57a424f922c971d3db3f856f8d54b0784bcc5d7182905c4237153c5d250b8aee1d26410b1dca7b1cb73*48*" +
		"74a060efbaf2c79d5523219d8162c425befbb2094fb46e7ffaedc7cd4f192e6f0c47d8aa91e0a3201346725d3ddadfff\n"

	src := candidates.Explicit("wrong", "vilefault")
	res, err := Process(context.Background(), bytes.NewReader([]byte(line)), int64(len(line)), src, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Root.Format != "dmg" {
		t.Fatalf("format = %q, want dmg", res.Root.Format)
	}
	if res.Root.Status != StatusDecrypted || res.Root.Password != "vilefault" {
		t.Fatalf("status=%v password=%q, want decrypted/vilefault", res.Root.Status, res.Root.Password)
	}
}
