package xcrack

import (
	stdzip "archive/zip"
	"bytes"
	"context"
	"hash/crc32"
	"testing"

	"github.com/rom/xcrypto/candidates"
	"github.com/rom/xcrypto/scheme/zipcrypto"
)

// buildStoredZipCrypto builds a ZIP with one STORED (uncompressed) ZipCrypto
// entry. For STORED, the encrypted data stream is the file content itself, so the
// content doubles as known plaintext. It returns the archive and the keys bkcrack
// would recover (the state before the data, i.e. after the 12-byte header).
func buildStoredZipCrypto(t *testing.T, name, pw string, content []byte) (archive []byte, keysBeforeData zipcrypto.Keys) {
	t.Helper()
	crc := crc32.ChecksumIEEE(content)
	raw := zipcrypto.EncryptRaw([]byte(pw), make([]byte, zipcrypto.HeaderLen-1), byte(crc>>24), content)

	var b bytes.Buffer
	zw := stdzip.NewWriter(&b)
	fh := &stdzip.FileHeader{Name: name, Method: stdzip.Store}
	fh.Flags |= 0x1 // encrypted
	fh.CRC32 = crc
	fh.UncompressedSize64 = uint64(len(content))
	fh.CompressedSize64 = uint64(len(raw))
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	// State before the data = NewKeys advanced through the 12-byte header.
	k := zipcrypto.NewKeys([]byte(pw))
	k.Decrypt(append([]byte(nil), raw[:zipcrypto.HeaderLen]...))
	return b.Bytes(), k
}

// fakeOffloader returns fixed keys (as if an external engine found them). The
// engine re-validates them, so the test still exercises the real validation path.
type fakeOffloader struct{ keys zipcrypto.Keys }

func (f fakeOffloader) Recover(plain, cipher []byte) (zipcrypto.Keys, bool, error) {
	return f.keys, true, nil
}

// TestEngineKnownPlaintextRecovery proves the engine unlocks a ZipCrypto entry
// from known plaintext with NO password candidate supplied.
func TestEngineKnownPlaintextRecovery(t *testing.T) {
	content := []byte("CONFIDENTIAL: the quick brown fox jumps over the lazy dog 0123456789")
	archive, keys := buildStoredZipCrypto(t, "secret.txt", "s3kr1t-passphrase", content)

	opts := Options{
		// No wordlist, no passwords: recovery must come from the known plaintext.
		KnownPlaintext: KnownPlaintext{
			For:     func(path string) []byte { return content },
			Offload: fakeOffloader{keys: keys},
		},
	}
	var foundKR bool
	opts.OnFound = func(f Found) {
		if f.KeyRecovered {
			foundKR = true
		}
	}

	res, err := Process(context.Background(), bytes.NewReader(archive), int64(len(archive)), candidates.Explicit(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	if len(res.Root.Children) != 1 {
		t.Fatalf("got %d children, want 1", len(res.Root.Children))
	}
	ch := res.Root.Children[0]
	if ch.Status != StatusDecrypted {
		t.Fatalf("status = %v, want decrypted", ch.Status)
	}
	if !ch.KeyRecovered {
		t.Fatal("node not marked KeyRecovered")
	}
	if ch.Password != "" {
		t.Fatalf("password = %q, want empty (no password used)", ch.Password)
	}
	if !foundKR {
		t.Fatal("OnFound did not report KeyRecovered")
	}
	rc, _ := ch.Content.Open()
	if got := readAll(t, rc); !bytes.Equal(got, content) {
		t.Fatalf("content mismatch:\n got %q\nwant %q", got, content)
	}
}

// TestEngineKnownPlaintextWrongStillLocks checks that a wrong known plaintext
// does not falsely unlock the entry: the recovery re-validates and, since no
// password is supplied either, the entry stays locked.
func TestEngineKnownPlaintextWrongStillLocks(t *testing.T) {
	content := []byte("CONFIDENTIAL: the quick brown fox jumps over the lazy dog 0123456789")
	archive, keys := buildStoredZipCrypto(t, "secret.txt", "s3kr1t-passphrase", content)

	opts := Options{
		KnownPlaintext: KnownPlaintext{
			// Wrong known plaintext (does not match the entry's bytes).
			For:     func(path string) []byte { return bytes.Repeat([]byte("X"), len(content)) },
			Offload: fakeOffloader{keys: keys}, // even with "keys", validation must reject
		},
	}
	res, err := Process(context.Background(), bytes.NewReader(archive), int64(len(archive)), candidates.Explicit(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Close()

	ch := res.Root.Children[0]
	if ch.Status == StatusDecrypted || ch.KeyRecovered {
		t.Fatalf("wrong known plaintext falsely unlocked the entry (status=%v, kr=%v)", ch.Status, ch.KeyRecovered)
	}
}
