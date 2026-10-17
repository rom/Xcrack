package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// makeSelfSigned returns a PEM-encoded self-signed CA certificate, usable as a
// client-CA bundle in tests.
func makeSelfSigned(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Xcrack Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestServerTLSConfigMinVersion(t *testing.T) {
	for in, want := range map[string]uint16{
		"":    tls.VersionTLS12,
		"1.2": tls.VersionTLS12,
		"1.3": tls.VersionTLS13,
	} {
		c, err := serverTLSConfig(in, "")
		if err != nil {
			t.Fatalf("minVer %q: %v", in, err)
		}
		if c.MinVersion != want {
			t.Errorf("minVer %q: MinVersion=%x want %x", in, c.MinVersion, want)
		}
		if c.ClientAuth != tls.NoClientCert {
			t.Errorf("minVer %q: unexpected client-auth without a client CA", in)
		}
	}
	if _, err := serverTLSConfig("1.1", ""); err == nil {
		t.Error("expected an error for an unsupported --tls-min-version")
	}
}

func TestServerTLSConfigMutualTLS(t *testing.T) {
	// A self-signed cert doubles as its own CA bundle for this test.
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	// Minimal valid PEM: generate one with the Go stdlib via tls, reusing a
	// throwaway self-signed cert is overkill; instead write a known-good PEM by
	// asking the stdlib to make one.
	cert := makeSelfSigned(t)
	if err := os.WriteFile(caPath, cert, 0o600); err != nil {
		t.Fatal(err)
	}

	c, err := serverTLSConfig("1.2", caPath)
	if err != nil {
		t.Fatalf("serverTLSConfig with client CA: %v", err)
	}
	if c.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth=%v, want RequireAndVerifyClientCert", c.ClientAuth)
	}
	if c.ClientCAs == nil {
		t.Error("ClientCAs pool not set")
	}

	// A CA file with no PEM certificates is an error.
	bad := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0o600)
	if _, err := serverTLSConfig("1.2", bad); err == nil {
		t.Error("expected an error for a CA file with no certificates")
	}
	if _, err := serverTLSConfig("1.2", filepath.Join(dir, "missing.pem")); err == nil {
		t.Error("expected an error for a missing CA file")
	}
}
