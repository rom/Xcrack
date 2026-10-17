package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrack/pkg/api"
	"github.com/rom/xcrack/pkg/xcrack"
)

func TestBuildClusterHTTPClientPlainDefault(t *testing.T) {
	c, err := buildClusterHTTPClient(tlsClientOpts{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if c == nil || c.Transport != nil {
		t.Fatalf("no TLS options should yield a plain default client, got %+v", c)
	}
}

func TestBuildClusterHTTPClientCertWithoutKey(t *testing.T) {
	if _, err := buildClusterHTTPClient(tlsClientOpts{CertFile: "c.pem"}, nil); err == nil {
		t.Fatal("expected an error when --tls-cert is set without --tls-key")
	}
}

func TestBuildClusterHTTPClientConfigFallback(t *testing.T) {
	// A bad CA path from the config must surface as an error (proving the config
	// fallback is consulted when the flag is empty).
	var cfg fileConfig
	cfg.Cluster.TLS.CA = "/nonexistent/ca.pem"
	if _, err := buildClusterHTTPClient(tlsClientOpts{}, &cfg); err == nil {
		t.Fatal("expected an error from the config-provided CA path")
	}
}

// writeServerCAPEM encodes a test TLS server's certificate as a PEM CA file.
func writeServerCAPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestClusterClientHTTPSRoundTrip proves the client TLS wiring end to end against
// a real HTTPS server running the xcrackd API handler: trusting the server's cert
// via --tls-ca works, an untrusted default client is rejected, and --tls-insecure
// bypasses verification.
func TestClusterClientHTTPSRoundTrip(t *testing.T) {
	pool := xcrack.NewPool(xcrack.Options{})
	defer pool.Close()
	ts := httptest.NewUnstartedServer(api.NewServer(pool, api.Config{}).Handler())
	ts.StartTLS()
	defer ts.Close()

	caPath := writeServerCAPEM(t, ts.Certificate())

	get := func(o tlsClientOpts) (int, error) {
		c, err := buildClusterHTTPClient(o, nil)
		if err != nil {
			return 0, err
		}
		resp, err := c.Get(ts.URL + "/v1/healthz")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	// Trusting the server's self-signed cert via --tls-ca works.
	if code, err := get(tlsClientOpts{CAFile: caPath}); err != nil || code != http.StatusOK {
		t.Fatalf("--tls-ca round trip: code=%d err=%v", code, err)
	}
	// The default client (system roots) must reject the untrusted cert.
	if _, err := get(tlsClientOpts{}); err == nil {
		t.Fatal("expected the untrusted self-signed server cert to be rejected by the default client")
	}
	// --tls-insecure bypasses verification.
	if code, err := get(tlsClientOpts{Insecure: true}); err != nil || code != http.StatusOK {
		t.Fatalf("--tls-insecure round trip: code=%d err=%v", code, err)
	}
}
