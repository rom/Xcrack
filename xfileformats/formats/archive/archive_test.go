package archive

import (
	stdtar "archive/tar"
	"bytes"
	stdgzip "compress/gzip"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rom/xfileformats"
)

func readEntry(t *testing.T, e *xfileformats.Entry) []byte {
	t.Helper()
	r, err := e.Open(nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func entriesOf(t *testing.T, f xfileformats.Container, data []byte) []*xfileformats.Entry {
	t.Helper()
	es, err := f.Entries(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	return es
}

func TestGzip(t *testing.T) {
	payload := bytes.Repeat([]byte("gzip payload "), 100)
	var b bytes.Buffer
	gw := stdgzip.NewWriter(&b)
	gw.Name = "inner.bin"
	gw.Write(payload)
	gw.Close()

	f := gzipFormat{}
	if _, ok := f.Detect(b.Bytes()); !ok {
		t.Fatal("gzip not detected")
	}
	es := entriesOf(t, f, b.Bytes())
	if len(es) != 1 || es[0].Path != "inner.bin" {
		t.Fatalf("entries = %+v", es)
	}
	if got := readEntry(t, es[0]); !bytes.Equal(got, payload) {
		t.Fatal("gzip content mismatch")
	}
}

func TestTar(t *testing.T) {
	files := map[string][]byte{"a/x.txt": []byte("alpha"), "b/y.bin": bytes.Repeat([]byte("Z"), 1000)}
	var b bytes.Buffer
	tw := stdtar.NewWriter(&b)
	order := []string{"a/x.txt", "b/y.bin"}
	for _, name := range order {
		tw.WriteHeader(&stdtar.Header{Name: name, Mode: 0o600, Size: int64(len(files[name])), Typeflag: stdtar.TypeReg})
		tw.Write(files[name])
	}
	tw.Close()

	f := tarFormat{}
	if _, ok := f.Detect(b.Bytes()); !ok {
		t.Fatal("tar not detected")
	}
	es := entriesOf(t, f, b.Bytes())
	if len(es) != 2 {
		t.Fatalf("got %d entries, want 2", len(es))
	}
	for _, e := range es {
		if got := readEntry(t, e); !bytes.Equal(got, files[e.Path]) {
			t.Errorf("%s content mismatch", e.Path)
		}
	}
}

func TestEML(t *testing.T) {
	msg := "From: a@example.com\r\n" +
		"To: b@example.com\r\n" +
		"Subject: test\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=BOUND\r\n" +
		"\r\n" +
		"--BOUND\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"the body text\r\n" +
		"--BOUND\r\n" +
		"Content-Type: application/octet-stream; name=\"evil.bin\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=\"evil.bin\"\r\n\r\n" +
		"aGVsbG8gbWFsd2FyZQ==\r\n" + // "hello malware"
		"--BOUND--\r\n"
	data := []byte(msg)

	f := emlFormat{}
	if _, ok := f.Detect(data); !ok {
		t.Fatal("eml not detected")
	}
	es := entriesOf(t, f, data)
	if len(es) != 2 {
		t.Fatalf("got %d parts, want 2; %+v", len(es), es)
	}
	var found bool
	for _, e := range es {
		if e.Path == "evil.bin" {
			found = true
			if got := readEntry(t, e); string(got) != "hello malware" {
				t.Fatalf("attachment decoded = %q", got)
			}
		}
	}
	if !found {
		t.Fatal("attachment evil.bin not extracted")
	}
}

func TestEMLDetectNotText(t *testing.T) {
	if _, ok := (emlFormat{}).Detect([]byte("just some plain text, not an email at all\n")); ok {
		t.Error("plain text should not detect as eml")
	}
}

func TestBzip2(t *testing.T) {
	bz, err := exec.LookPath("bzip2")
	if err != nil {
		t.Skip("bzip2 CLI not available")
	}
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("bzip2 payload "), 200)
	src := filepath.Join(dir, "p.bin")
	os.WriteFile(src, payload, 0o600)
	if out, err := exec.Command(bz, "-k", "-f", src).CombinedOutput(); err != nil {
		t.Fatalf("bzip2: %v\n%s", err, out)
	}
	data, err := os.ReadFile(src + ".bz2")
	if err != nil {
		t.Fatal(err)
	}
	f := bzip2Format{}
	if _, ok := f.Detect(data); !ok {
		t.Fatal("bzip2 not detected")
	}
	es := entriesOf(t, f, data)
	if len(es) != 1 {
		t.Fatalf("got %d entries", len(es))
	}
	if got := readEntry(t, es[0]); !bytes.Equal(got, payload) {
		t.Fatal("bzip2 content mismatch")
	}
}

func TestXZ(t *testing.T) {
	xzBin, err := exec.LookPath("xz")
	if err != nil {
		t.Skip("xz CLI not available")
	}
	dir := t.TempDir()
	payload := bytes.Repeat([]byte("xz payload "), 300)
	src := filepath.Join(dir, "p.bin")
	os.WriteFile(src, payload, 0o600)
	if out, err := exec.Command(xzBin, "-k", "-f", src).CombinedOutput(); err != nil {
		t.Fatalf("xz: %v\n%s", err, out)
	}
	data, err := os.ReadFile(src + ".xz")
	if err != nil {
		t.Fatal(err)
	}
	f := xzFormat{}
	if _, ok := f.Detect(data); !ok {
		t.Fatal("xz not detected")
	}
	es := entriesOf(t, f, data)
	if len(es) != 1 {
		t.Fatalf("got %d entries", len(es))
	}
	if got := readEntry(t, es[0]); !bytes.Equal(got, payload) {
		t.Fatal("xz content mismatch")
	}
}

func findEntry(es []*xfileformats.Entry, name string) *xfileformats.Entry {
	for _, e := range es {
		if e.Path == name {
			return e
		}
	}
	return nil
}

func TestSevenZipEncrypted(t *testing.T) {
	bin, err := exec.LookPath("7z")
	if err != nil {
		t.Skip("7z CLI not available")
	}
	dir := t.TempDir()
	content := bytes.Repeat([]byte("7z secret payload "), 50)
	os.WriteFile(filepath.Join(dir, "secret.txt"), content, 0o600)
	cmd := exec.Command(bin, "a", "-pHunter2", "arc.7z", "secret.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("7z: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "arc.7z"))
	if err != nil {
		t.Fatal(err)
	}
	es := entriesOf(t, sevenzipFormat{}, data)
	e := findEntry(es, "secret.txt")
	if e == nil || !e.Encrypted {
		t.Fatalf("secret.txt encrypted entry not found: %+v", es)
	}
	if ok, err := e.Verify([]byte("Hunter2")); err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	if ok, _ := e.Verify([]byte("wrong")); ok {
		t.Fatal("Verify(wrong) = true")
	}
	if got := readEntryPw(t, e, "Hunter2"); !bytes.Equal(got, content) {
		t.Fatal("7z content mismatch")
	}
}

func TestRarEncrypted(t *testing.T) {
	bin, err := exec.LookPath("rar")
	if err != nil {
		t.Skip("rar CLI not available")
	}
	dir := t.TempDir()
	content := bytes.Repeat([]byte("rar secret payload "), 50)
	os.WriteFile(filepath.Join(dir, "secret.txt"), content, 0o600)
	cmd := exec.Command(bin, "a", "-pHunter2", "arc.rar", "secret.txt")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("rar: %v\n%s", err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "arc.rar"))
	if err != nil {
		t.Fatal(err)
	}
	es := entriesOf(t, rarFormat{}, data)
	e := findEntry(es, "secret.txt")
	if e == nil || !e.Encrypted {
		t.Fatalf("secret.txt encrypted entry not found: %+v", es)
	}
	if ok, err := e.Verify([]byte("Hunter2")); err != nil || !ok {
		t.Fatalf("Verify(correct): ok=%v err=%v", ok, err)
	}
	if ok, _ := e.Verify([]byte("wrong")); ok {
		t.Fatal("Verify(wrong) = true")
	}
	if got := readEntryPw(t, e, "Hunter2"); !bytes.Equal(got, content) {
		t.Fatal("rar content mismatch")
	}
}

func readEntryPw(t *testing.T, e *xfileformats.Entry, pw string) []byte {
	t.Helper()
	r, err := e.Open([]byte(pw))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
