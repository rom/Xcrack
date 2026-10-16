package archive

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xfileformats"
)

const hdrPass = "Hunter2"
const hdrContent = "secret payload inside an encrypted-header archive\n"

func readTarMember(t *testing.T, data []byte, name string) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		if h.Name == name {
			b, _ := io.ReadAll(tr)
			return b
		}
	}
	return nil
}

func testHeaderEncrypted(t *testing.T, fixture string, fmt xfileformats.Container) {
	data, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	entries, err := fmt.Entries(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || !entries[0].Encrypted {
		t.Fatalf("expected one gated encrypted entry, got %+v", entries)
	}
	e := entries[0]
	if ok, _ := e.Verify([]byte("wrong")); ok {
		t.Fatal("Verify accepted a wrong password")
	}
	ok, err := e.Verify([]byte(hdrPass))
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want ok", ok, err)
	}
	r, err := e.Open([]byte(hdrPass))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	tarBytes, _ := io.ReadAll(r)
	got := readTarMember(t, tarBytes, "doc.txt")
	if !bytes.Equal(got, []byte(hdrContent)) {
		t.Fatalf("decrypted member = %q, want %q", got, hdrContent)
	}
}

func TestHeaderEncrypted7z(t *testing.T) { testHeaderEncrypted(t, "hdr.7z", sevenzipFormat{}) }
func TestHeaderEncryptedRar(t *testing.T) {
	if _, err := os.Stat(filepath.Join("testdata", "hdr.rar")); err != nil {
		t.Skip("rar fixture unavailable")
	}
	testHeaderEncrypted(t, "hdr.rar", rarFormat{})
}
