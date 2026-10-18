//go:build tpm

package securecache

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

// TestTPMSeal exercises the real TPM sealer when a device is present. It is
// built only with -tags tpm and skips when no TPM is reachable, so it never
// blocks a machine without one. On a host with a (software or hardware) TPM it
// is a full seal→unseal and Store round-trip against the device.
func TestTPMSeal(t *testing.T) {
	sealer, err := TPMSealer()
	if errors.Is(err, ErrTPMUnavailable) {
		t.Skipf("no TPM available: %v", err)
	}
	if err != nil {
		t.Fatalf("TPMSealer: %v", err)
	}

	dek := bytes.Repeat([]byte{0xa5}, dekLen)
	blob, err := sealer.Seal(dek)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := sealer.Unseal(blob)
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("unsealed DEK mismatch: got %x want %x", got, dek)
	}

	path := filepath.Join(t.TempDir(), "found.sealed")
	s, err := Open(path, sealer)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.Add("tpm-secret"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	s2, err := Open(path, sealer)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if pw := s2.Passwords(); len(pw) != 1 || pw[0] != "tpm-secret" {
		t.Fatalf("recovered %v", pw)
	}
}
