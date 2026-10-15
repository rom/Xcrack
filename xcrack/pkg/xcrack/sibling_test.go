package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/scheme/zipcrypto"
)

// buildMultiPwZip builds a ZIP whose entries each have a DISTINCT ZipCrypto
// password, so cracking them in parallel forces concurrent iteration of the
// (cloned) candidate source.
func buildMultiPwZip(t *testing.T, names []string, pw, content map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	for _, name := range names {
		plain := content[name]
		crc := crc32.ChecksumIEEE(plain)
		var comp bytes.Buffer
		fw, _ := flate.NewWriter(&comp, flate.DefaultCompression)
		fw.Write(plain)
		fw.Close()
		raw := zipcrypto.EncryptRaw(pw[name], make([]byte, zipcrypto.HeaderLen-1), byte(crc>>24), comp.Bytes())
		fh := &stdzip.FileHeader{Name: name, Method: stdzip.Deflate}
		fh.Flags |= 0x1
		fh.CRC32 = crc
		fh.UncompressedSize64 = uint64(len(plain))
		fh.CompressedSize64 = uint64(len(raw))
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(raw)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestSiblingParallelism(t *testing.T) {
	const n = 12
	var names []string
	pw := map[string][]byte{}
	content := map[string][]byte{}
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("e%02d.txt", i)
		names = append(names, name)
		pw[name] = []byte(fmt.Sprintf("pw%02d", i))
		content[name] = []byte(fmt.Sprintf("payload for %s", name))
	}
	data := buildMultiPwZip(t, names, pw, content)

	// wordlist with decoys interleaved with the real passwords, so the base
	// search (not just promotion) is exercised per entry.
	var lines []string
	for i := 0; i < n; i++ {
		lines = append(lines, fmt.Sprintf("decoy%02da", i), fmt.Sprintf("pw%02d", i), fmt.Sprintf("decoy%02db", i))
	}
	wlPath := filepath.Join(t.TempDir(), "words.txt")
	if err := os.WriteFile(wlPath, []byte(joinNL(lines)), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Process(context.Background(), bytes.NewReader(data), int64(len(data)),
		candidates.File(wlPath), Options{FileConcurrency: 4, Workers: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	if len(res.Root.Children) != n {
		t.Fatalf("got %d children, want %d", len(res.Root.Children), n)
	}
	for i, child := range res.Root.Children {
		want := names[i]
		if filepath.Base(child.Path) != want {
			t.Errorf("child %d path = %q, want basename %q (order not preserved)", i, child.Path, want)
		}
		if child.Status != StatusDecrypted {
			t.Errorf("%s: status = %v, want decrypted", want, child.Status)
			continue
		}
		if child.Password != string(pw[want]) {
			t.Errorf("%s: password = %q, want %q", want, child.Password, pw[want])
		}
		if child.Content == nil {
			t.Errorf("%s: no content", want)
			continue
		}
		rc, _ := child.Content.Open()
		got := readAll(t, rc)
		if !bytes.Equal(got, content[want]) {
			t.Errorf("%s: content mismatch", want)
		}
	}
}

func joinNL(ss []string) string {
	out := ""
	for _, s := range ss {
		out += s + "\n"
	}
	return out
}
