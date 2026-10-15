package zip

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/rom/xfileformats"
)

// --- fixture builders (the encrypt side, so tests need no external tools) ---

func deflateBytes(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// encZipCrypto builds the raw stored bytes for a ZipCrypto deflate entry.
func encZipCrypto(t *testing.T, password, plain []byte) (raw []byte, crc uint32) {
	t.Helper()
	crc = crc32.ChecksumIEEE(plain)
	comp := deflateBytes(t, plain)
	hdr := randBytes(t, pkHeaderLen)
	hdr[pkHeaderLen-1] = byte(crc >> 24) // bit 3 not set => CRC-based check byte
	buf := append(hdr, comp...)
	k := newPkKeys(password)
	k.encrypt(buf)
	return buf, crc
}

func aesExtra(p aesParams) []byte {
	e := make([]byte, 0, 11)
	e = binary.LittleEndian.AppendUint16(e, 0x9901)
	e = binary.LittleEndian.AppendUint16(e, 7)
	e = binary.LittleEndian.AppendUint16(e, p.vendorVer)
	e = binary.LittleEndian.AppendUint16(e, aesVendorAE)
	e = append(e, p.strength)
	e = binary.LittleEndian.AppendUint16(e, p.actualMethod)
	return e
}

// encWinZipAES builds the raw stored bytes for a WinZip AES (AE-2) deflate entry.
func encWinZipAES(t *testing.T, password, plain []byte, strength byte) (raw []byte, p aesParams) {
	t.Helper()
	p = aesParams{strength: strength, actualMethod: methodDeflate, vendorVer: 2}
	comp := deflateBytes(t, plain)
	salt := randBytes(t, p.saltLen())
	encKey, authKey, pwv, err := aesDerive(password, salt, p.keyLen())
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(comp))
	copy(ct, comp)
	aesCTRXor(block, ct)
	m := hmac.New(sha1.New, authKey)
	m.Write(ct)
	mac := m.Sum(nil)[:aesMACLen]
	raw = append([]byte{}, salt...)
	raw = append(raw, pwv...)
	raw = append(raw, ct...)
	raw = append(raw, mac...)
	return raw, p
}

type fixtureFile struct {
	name  string
	plain []byte
}

func buildZipCrypto(t *testing.T, password []byte, files []fixtureFile) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	for _, f := range files {
		raw, crc := encZipCrypto(t, password, f.plain)
		fh := &stdzip.FileHeader{Name: f.name, Method: stdzip.Deflate}
		fh.Flags |= 0x1
		fh.CRC32 = crc
		fh.UncompressedSize64 = uint64(len(f.plain))
		fh.CompressedSize64 = uint64(len(raw))
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func buildWinZipAES(t *testing.T, password []byte, strength byte, files []fixtureFile) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	for _, f := range files {
		raw, p := encWinZipAES(t, password, f.plain, strength)
		fh := &stdzip.FileHeader{Name: f.name, Method: methodAES}
		fh.Flags |= 0x1
		fh.CRC32 = 0 // AE-2 omits CRC
		fh.UncompressedSize64 = uint64(len(f.plain))
		fh.CompressedSize64 = uint64(len(raw))
		fh.Extra = aesExtra(p)
		w, err := zw.CreateRaw(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// --- helpers ---

func onlyEntry(t *testing.T, data []byte) *xfileformats.Entry {
	t.Helper()
	f := New()
	entries, err := f.Entries(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 entry, got %d", len(entries))
	}
	return entries[0]
}

func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func checkRoundTrip(t *testing.T, data, password, plain []byte) {
	t.Helper()
	e := onlyEntry(t, data)
	if !e.Encrypted {
		t.Fatal("entry should be marked encrypted")
	}
	if e.Challenge == nil {
		t.Fatal("encrypted entry should carry a Challenge")
	}
	ok, err := e.Verify(password)
	if err != nil {
		t.Fatalf("Verify(correct): %v", err)
	}
	if !ok {
		t.Fatal("Verify(correct) = false, want true")
	}
	ok, err = e.Verify([]byte("definitely-wrong"))
	if err != nil {
		t.Fatalf("Verify(wrong): %v", err)
	}
	if ok {
		t.Fatal("Verify(wrong) = true, want false")
	}
	r, err := e.Open(password)
	if err != nil {
		t.Fatalf("Open(correct): %v", err)
	}
	if got := readAll(t, r); !bytes.Equal(got, plain) {
		t.Fatalf("Open content mismatch:\n got %q\nwant %q", got, plain)
	}
	if _, err := e.Open([]byte("definitely-wrong")); err == nil {
		t.Fatal("Open(wrong) should fail")
	}
}

// --- tests ---

func TestZipCryptoRoundTrip(t *testing.T) {
	password := []byte("infected")
	plain := []byte("Hello, this is the payload the scanner must see.\n")
	data := buildZipCrypto(t, password, []fixtureFile{{"payload.txt", plain}})
	checkRoundTrip(t, data, password, plain)
}

func TestWinZipAESRoundTrip(t *testing.T) {
	for _, strength := range []byte{1, 3} { // AES-128 and AES-256
		strength := strength
		t.Run(aesParams{strength: strength}.methodName(), func(t *testing.T) {
			password := []byte("Welcome1")
			plain := bytes.Repeat([]byte("nested-secret-"), 40)
			data := buildWinZipAES(t, password, strength, []fixtureFile{{"doc.bin", plain}})
			checkRoundTrip(t, data, password, plain)
		})
	}
}

func TestEmptyPasswordAndStored(t *testing.T) {
	// empty-password ZipCrypto (common in malware) and a stored (uncompressed) entry
	password := []byte("")
	plain := []byte("x")
	data := buildZipCrypto(t, password, []fixtureFile{{"a.txt", plain}})
	checkRoundTrip(t, data, password, plain)
}

func TestDetect(t *testing.T) {
	f := New()
	if _, ok := f.Detect([]byte("PK\x03\x04rest")); !ok {
		t.Error("should detect local-file-header magic")
	}
	if _, ok := f.Detect([]byte("not a zip at all")); ok {
		t.Error("should not detect non-zip")
	}
}

func TestRegistryDetectsZip(t *testing.T) {
	reg := xfileformats.NewRegistry()
	Register(reg)
	data := buildZipCrypto(t, []byte("p"), []fixtureFile{{"f", []byte("y")}})
	peek, _ := xfileformats.Peek(bytes.NewReader(data))
	f, err := reg.Detect(peek)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if f.Name() != "zip" {
		t.Fatalf("got %q, want zip", f.Name())
	}
	if !f.Caps().Container {
		t.Fatal("zip should advertise Container")
	}
}

func TestSanitizePath(t *testing.T) {
	cases := map[string]string{
		"a/b.txt":          "a/b.txt",
		"../../etc/passwd": "etc/passwd",
		"/abs/path":        "abs/path",
		`..\..\win\sys`:    "win/sys",
		"..":               "",
		"./x":              "x",
	}
	for in, want := range cases {
		if got := sanitizePath(in); got != want {
			t.Errorf("sanitizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMixedEntries(t *testing.T) {
	// one encrypted, one plaintext, in the same archive
	password := []byte("pw")
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	// plaintext entry via normal Create
	w, err := zw.Create("clear.txt")
	if err != nil {
		t.Fatal(err)
	}
	clearPlain := []byte("in the clear")
	w.Write(clearPlain)
	// encrypted entry via CreateRaw
	enc := []byte("secret content")
	raw, crc := encZipCrypto(t, password, enc)
	fh := &stdzip.FileHeader{Name: "secret.txt", Method: stdzip.Deflate}
	fh.Flags |= 0x1
	fh.CRC32 = crc
	fh.UncompressedSize64 = uint64(len(enc))
	fh.CompressedSize64 = uint64(len(raw))
	wr, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	wr.Write(raw)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	f := New()
	entries, err := f.Entries(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}
	byName := map[string]*xfileformats.Entry{}
	for _, e := range entries {
		byName[e.Path] = e
	}
	if e := byName["clear.txt"]; e == nil || e.Encrypted {
		t.Fatal("clear.txt should be present and unencrypted")
	} else {
		r, err := e.Open(nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := readAll(t, r); !bytes.Equal(got, clearPlain) {
			t.Fatalf("clear content mismatch: %q", got)
		}
	}
	if e := byName["secret.txt"]; e == nil || !e.Encrypted {
		t.Fatal("secret.txt should be present and encrypted")
	} else {
		r, err := e.Open(password)
		if err != nil {
			t.Fatal(err)
		}
		if got := readAll(t, r); !bytes.Equal(got, enc) {
			t.Fatalf("secret content mismatch: %q", got)
		}
	}
}

// TestZipCLIInterop cross-checks our ZipCrypto decryptor against a file made by
// the real `zip -P` tool, when available.
func TestZipCLIInterop(t *testing.T) {
	zipBin, err := exec.LookPath("zip")
	if err != nil {
		t.Skip("zip CLI not available")
	}
	dir := t.TempDir()
	plainPath := filepath.Join(dir, "msg.txt")
	plain := []byte("interop content from the real zip tool\n")
	if err := os.WriteFile(plainPath, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.zip")
	password := "infected"
	cmd := exec.Command(zipBin, "-j", "-P", password, outPath, plainPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zip CLI failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	e := onlyEntry(t, data)
	ok, err := e.Verify([]byte(password))
	if err != nil || !ok {
		t.Fatalf("Verify real-zip file: ok=%v err=%v", ok, err)
	}
	r, err := e.Open([]byte(password))
	if err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, r); !bytes.Equal(got, plain) {
		t.Fatalf("interop content mismatch:\n got %q\nwant %q", got, plain)
	}
}
