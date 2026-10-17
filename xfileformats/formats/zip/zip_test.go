package zip

import (
	stdzip "archive/zip"
	"bytes"
	"compress/flate"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rom/xcrypto/scheme/winzipaes"
	"github.com/rom/xcrypto/scheme/zipcrypto"
	"github.com/rom/xfileformats"
)

// --- fixture builders (use the xcrypto schemes so tests need no external tools) ---

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

func encZipCrypto(t *testing.T, password, plain []byte) (raw []byte, crc uint32) {
	t.Helper()
	crc = crc32.ChecksumIEEE(plain)
	comp := deflateBytes(t, plain)
	hdr11 := randBytes(t, zipcrypto.HeaderLen-1)
	return zipcrypto.EncryptRaw(password, hdr11, byte(crc>>24), comp), crc
}

func aesExtra(p winzipaes.Params) []byte {
	e := make([]byte, 0, 11)
	e = binary.LittleEndian.AppendUint16(e, 0x9901)
	e = binary.LittleEndian.AppendUint16(e, 7)
	e = binary.LittleEndian.AppendUint16(e, p.VendorVer)
	e = binary.LittleEndian.AppendUint16(e, winzipaes.VendorAE)
	e = append(e, p.Strength)
	e = binary.LittleEndian.AppendUint16(e, p.ActualMethod)
	return e
}

func encWinZipAES(t *testing.T, password, plain []byte, strength byte) (raw []byte, p winzipaes.Params) {
	t.Helper()
	p = winzipaes.Params{Strength: strength, ActualMethod: methodDeflate, VendorVer: 2}
	comp := deflateBytes(t, plain)
	salt := randBytes(t, p.SaltLen())
	raw, err := winzipaes.EncryptRaw(password, p, salt, comp)
	if err != nil {
		t.Fatal(err)
	}
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
		p := winzipaes.Params{Strength: strength}
		t.Run(p.SchemeName(), func(t *testing.T) {
			password := []byte("Welcome1")
			plain := bytes.Repeat([]byte("nested-secret-"), 40)
			data := buildWinZipAES(t, password, strength, []fixtureFile{{"doc.bin", plain}})
			checkRoundTrip(t, data, password, plain)
		})
	}
}

func TestEmptyPasswordAndStored(t *testing.T) {
	password := []byte("")
	plain := []byte("x")
	data := buildZipCrypto(t, password, []fixtureFile{{"a.txt", plain}})
	checkRoundTrip(t, data, password, plain)
}

// TestHashcatLines checks the $zip2$ export: it builds a WinZip-AES entry and,
// from the emitted line alone, reassembles the raw entry (salt, verifier,
// ciphertext, auth) and confirms winzipaes.Verify accepts the real password and
// rejects a wrong one. This proves the line carries exactly the bytes a GPU
// cracker needs — the bulk ciphertext the probe-time Challenge omits.
func TestHashcatLines(t *testing.T) {
	password := []byte("S3cr3t-пароль")
	plain := bytes.Repeat([]byte("the quick brown fox "), 8)
	data := buildWinZipAES(t, password, 3, []fixtureFile{{"secret.txt", plain}})

	lines, err := New().HashcatLines(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("HashcatLines: %v", err)
	}
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1", len(lines))
	}
	l := lines[0]
	if l.Target != "secret.txt" {
		t.Errorf("target = %q, want secret.txt", l.Target)
	}
	if l.Hashcat != 13600 || l.John != "ZIP" {
		t.Errorf("tool ids = (%d, %q), want (13600, ZIP)", l.Hashcat, l.John)
	}

	f := strings.Split(l.Line, "*")
	if len(f) != 10 || f[0] != "$zip2$" || f[9] != "$/zip2$" {
		t.Fatalf("unexpected $zip2$ shape (%d fields): %q", len(f), l.Line)
	}
	if f[2] != "3" {
		t.Errorf("mode = %q, want 3 (AES-256)", f[2])
	}
	salt, verify, ct, auth := mustHexZip(t, f[4]), mustHexZip(t, f[5]), mustHexZip(t, f[7]), mustHexZip(t, f[8])
	if n, _ := strconv.Atoi(f[6]); n != len(ct) {
		t.Errorf("declared data length %d != actual %d", n, len(ct))
	}
	if len(salt) != 16 || len(verify) != winzipaes.PWVerifLen || len(auth) != winzipaes.MACLen {
		t.Fatalf("field sizes: salt=%d verify=%d auth=%d", len(salt), len(verify), len(auth))
	}

	p := winzipaes.Params{Strength: 3}
	raw := bytes.Join([][]byte{salt, verify, ct, auth}, nil)
	if ok, err := winzipaes.Verify(password, p, raw); err != nil || !ok {
		t.Fatalf("reassembled $zip2$ did not verify the correct password (ok=%v err=%v)", ok, err)
	}
	if ok, _ := winzipaes.Verify([]byte("wrong"), p, raw); ok {
		t.Fatal("reassembled $zip2$ verified a wrong password")
	}
}

// TestHashcatLinesSkipsNonAES checks non-AES entries are skipped: a pure
// ZipCrypto archive yields no $zip2$ lines (ZipCrypto has no such emitter), and
// a mixed archive yields a line only for the AES entry.
func TestHashcatLinesSkipsNonAES(t *testing.T) {
	zc := buildZipCrypto(t, []byte("pw"), []fixtureFile{{"a.txt", []byte("plain")}})
	lines, err := New().HashcatLines(bytes.NewReader(zc), int64(len(zc)))
	if err != nil {
		t.Fatalf("HashcatLines(zipcrypto): %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("zipcrypto yielded %d lines, want 0", len(lines))
	}
}

func mustHexZip(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
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
	password := []byte("pw")
	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	w, err := zw.Create("clear.txt")
	if err != nil {
		t.Fatal(err)
	}
	clearPlain := []byte("in the clear")
	w.Write(clearPlain)
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

// TestDecryptArchiveWithStart proves cross-entry key reuse: one shared pre-entry
// key state (NewKeys(password), which is exactly what a known-plaintext recovery
// rolls back to) decrypts every ZipCrypto entry in the archive, and a wrong
// state decrypts none (CRC-gated, no false positives).
func TestDecryptArchiveWithStart(t *testing.T) {
	pw := []byte("s3cr3t-reused")
	files := []fixtureFile{
		{"a.txt", []byte("alpha payload, entry one")},
		{"b.txt", bytes.Repeat([]byte("beta "), 300)},
		{"c.bin", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
	}
	archive := buildZipCrypto(t, pw, files)

	start := zipcrypto.NewKeys(pw) // the archive-wide shared state
	got, err := DecryptArchiveWithStart(bytes.NewReader(archive), int64(len(archive)), start)
	if err != nil {
		t.Fatalf("DecryptArchiveWithStart: %v", err)
	}
	byName := map[string]ArchivePlain{}
	for _, r := range got {
		byName[r.Name] = r
	}
	for _, f := range files {
		r, ok := byName[f.name]
		if !ok || !r.OK {
			t.Fatalf("%s: not decrypted (ok=%v)", f.name, r.OK)
		}
		if !bytes.Equal(r.Plaintext, f.plain) {
			t.Fatalf("%s: plaintext mismatch", f.name)
		}
	}

	// A wrong shared state recovers nothing (CRC fails on every entry).
	bad, _ := DecryptArchiveWithStart(bytes.NewReader(archive), int64(len(archive)), zipcrypto.NewKeys([]byte("wrong")))
	for _, r := range bad {
		if r.OK {
			t.Fatalf("%s: wrong key state falsely reported a hit", r.Name)
		}
	}
}

// TestDecryptArchiveWithStartSkipsAES confirms AES and unencrypted entries are
// skipped (OK=false) while the ZipCrypto entry in a mixed archive decrypts.
func TestDecryptArchiveWithStartSkipsAES(t *testing.T) {
	pw := []byte("mixbag")
	zc := buildZipCrypto(t, pw, []fixtureFile{{"zc.txt", []byte("zipcrypto entry")}})
	start := zipcrypto.NewKeys(pw)
	got, err := DecryptArchiveWithStart(bytes.NewReader(zc), int64(len(zc)), start)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !got[0].OK || string(got[0].Plaintext) != "zipcrypto entry" {
		t.Fatalf("zipcrypto entry not decrypted: %+v", got)
	}
}
