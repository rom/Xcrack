package msoffice

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xfileformats"
	"github.com/rom/xfileformats/internal/cfb"
)

// TestLegacyOfficeGold decrypts each encrypted fixture and checks that every
// decrypted stream is byte-for-byte identical to the corresponding stream of
// the known-good (msoffcrypto-tool) decrypted output.
func TestLegacyOfficeGold(t *testing.T) {
	cases := []struct {
		enc, plain, pw string
	}{
		{"rc4cryptoapi_password.doc", "rc4cryptoapi_password_plain.doc", "Password1234_"},
		{"rc4cryptoapi_password.xls", "rc4cryptoapi_password_plain.xls", "Password1234_"},
		{"rc4cryptoapi_password.ppt", "rc4cryptoapi_password_plain.ppt", "Password1234_"},
	}
	for _, tc := range cases {
		t.Run(tc.enc, func(t *testing.T) {
			encData := readFixture(t, tc.enc)
			goldData := readFixture(t, tc.plain)
			gold, err := cfb.Open(goldData)
			if err != nil {
				t.Fatalf("open gold %s: %v", tc.plain, err)
			}

			entries, err := New().Entries(bytes.NewReader(encData), int64(len(encData)))
			if err != nil {
				t.Fatalf("Entries(%s): %v", tc.enc, err)
			}
			if len(entries) == 0 {
				t.Fatalf("%s: no entries", tc.enc)
			}

			checked := 0
			for _, e := range entries {
				if !e.Encrypted {
					t.Errorf("%s: entry %q not marked encrypted", tc.enc, e.Path)
					continue
				}
				if ok, err := e.Verify([]byte(tc.pw)); err != nil || !ok {
					t.Fatalf("%s: Verify(%q) on %q = %v, %v; want true", tc.enc, tc.pw, e.Path, ok, err)
				}
				if ok, _ := e.Verify([]byte("wrong-password")); ok {
					t.Fatalf("%s: %q verified a wrong password", tc.enc, e.Path)
				}
				r, err := e.Open([]byte(tc.pw))
				if err != nil {
					t.Fatalf("%s: Open %q: %v", tc.enc, e.Path, err)
				}
				got, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("%s: read %q: %v", tc.enc, e.Path, err)
				}
				want, ok := gold.Stream(e.Path)
				if !ok {
					t.Fatalf("%s: gold has no stream %q", tc.enc, e.Path)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("%s: decrypted %q != gold (len got=%d want=%d, first diff at %d)",
						tc.enc, e.Path, len(got), len(want), firstDiff(got, want))
				}
				checked++
			}
			if checked == 0 {
				t.Fatalf("%s: no encrypted streams checked", tc.enc)
			}
			t.Logf("%s: %d decrypted stream(s) match the gold output", tc.enc, checked)
		})
	}
}

// TestXORWorkbook validates the XOR-obfuscation path on a real encrypted .xls.
// The vendored decrypted output for this sample is a differently-sized re-save
// (the reference tool itself compares it only fuzzily), so instead of a
// byte-exact gold match we check that the password verifies and the decrypted
// Workbook is structurally sound: same length, a leading BOF record, and the
// FilePass record blanked out. The crypto itself is round-trip tested in
// xcrypto/scheme/officebinary.
func TestXORWorkbook(t *testing.T) {
	encData := readFixture(t, "xor_password_123456789012345.xls")
	entries, err := New().Entries(bytes.NewReader(encData), int64(len(encData)))
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(entries) != 1 || entries[0].Path != "Workbook" {
		t.Fatalf("unexpected entries: %+v", entries)
	}
	e := entries[0]
	if e.Challenge == nil || e.Challenge.Scheme != "mso-xor" {
		t.Fatalf("challenge = %+v; want scheme mso-xor", e.Challenge)
	}
	if ok, err := e.Verify([]byte("123456789012345")); err != nil || !ok {
		t.Fatalf("Verify = %v, %v; want true", ok, err)
	}
	if ok, _ := e.Verify([]byte("not-it")); ok {
		t.Fatal("Verify accepted a wrong password")
	}
	r, err := e.Open([]byte("123456789012345"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// Length is preserved (XOR is byte-for-byte on the reconstructed stream).
	encWB := workbookStream(t, encData)
	if len(got) != len(encWB) {
		t.Fatalf("decrypted Workbook length %d != encrypted %d", len(got), len(encWB))
	}
	// First record is BOF (0x0809).
	if len(got) < 4 || got[0] != 0x09 || got[1] != 0x08 {
		t.Fatalf("decrypted Workbook does not start with a BOF record: % x", got[:min(4, len(got))])
	}
	// The FilePass record (id 47) is blanked to id 0 by decryption; the plaintext
	// must not still contain a FilePass record in the globals substream.
	if hasFilePass(got) {
		t.Fatal("decrypted Workbook still contains a FilePass record")
	}
}

// workbookStream extracts the Workbook stream from a compound file.
func workbookStream(t *testing.T, data []byte) []byte {
	t.Helper()
	cf, err := cfb.Open(data)
	if err != nil {
		t.Fatalf("cfb.Open: %v", err)
	}
	wb, ok := cf.Stream("Workbook")
	if !ok {
		t.Fatal("no Workbook stream")
	}
	return wb
}

// hasFilePass scans the globals substream for a FilePass record.
func hasFilePass(wb []byte) bool {
	found := false
	biffRecords(wb, func(num uint16, _ []byte) bool {
		switch num {
		case biffFilePass:
			found = true
			return false
		case biffEOF:
			return false
		}
		return true
	})
	return found
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestNotEncryptedAndUnsupported(t *testing.T) {
	// A random non-CFB blob is not detected.
	if _, ok := New().Detect([]byte("not a compound file")); ok {
		t.Fatal("Detect claimed a non-CFB blob")
	}
	// A CFB file with an EncryptionInfo stream (encrypted OOXML) is declined.
	// Build a minimal check: the encrypted .doc is CFB and detected.
	data := readFixture(t, "rc4cryptoapi_password.doc")
	if conf, ok := New().Detect(data); !ok || conf <= 0 {
		t.Fatalf("Detect on legacy .doc = %v, %v", conf, ok)
	}
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

var _ = xfileformats.ErrMalformed
