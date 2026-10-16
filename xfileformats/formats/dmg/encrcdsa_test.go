package dmg

import (
	"bytes"
	"os"
	"testing"
)

// TestEncrcdsaOnDisk parses real on-disk encrcdsa v2 containers (AES-128 and
// AES-256) and verifies the password. The fixtures were carved from genuine
// macOS-produced encrypted DMGs — real salt, IV, wrapped key blob, iteration
// count and data chunk — laid out per filevault.h with the datasize set so the
// parser reads that one chunk (see testdata/ATTRIBUTION.md). The password is
// "opensesame".
func TestEncrcdsaOnDisk(t *testing.T) {
	for _, tc := range []struct {
		file   string
		scheme string
	}{
		{"testdata/encrcdsa-aes256.dmg", "dmg-v2"},
		{"testdata/encrcdsa-aes128.dmg", "dmg-v2"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(tc.file)
			if err != nil {
				t.Fatal(err)
			}
			f := New()
			if _, ok := f.Detect(data[:16]); !ok {
				t.Fatal("Detect did not claim the encrcdsa container")
			}
			ch, err := f.Probe(bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if ch.Scheme != tc.scheme {
				t.Errorf("scheme = %q, want %q", ch.Scheme, tc.scheme)
			}
			ok, key, err := f.Verify(ch, []byte("opensesame"))
			if err != nil || !ok {
				t.Fatalf("Verify(correct) = (%v, %v)", ok, err)
			}
			if string(key) != "opensesame" {
				t.Errorf("recovered key = %q", key)
			}
			if ok, _, _ := f.Verify(ch, []byte("wrongpassword")); ok {
				t.Error("Verify(wrong) = true (false positive)")
			}
		})
	}
}
