package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rom/xcrack/pkg/xcrack"
)

func newTestServer(cfg Config) *httptest.Server {
	pool := xcrack.NewPool(xcrack.Options{Workers: 2, MaxProcs: 2})
	return httptest.NewServer(NewServer(pool, cfg).Handler())
}

func encryptedDoc(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join("..", "..", "..", "xfileformats", "formats", "msoffice", "testdata", "rc4cryptoapi_password.doc")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Skipf("fixture unavailable: %v", err)
	}
	return b
}

func TestHealth(t *testing.T) {
	ts := newTestServer(Config{})
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/v1/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestDecryptRecoversPassword(t *testing.T) {
	data := encryptedDoc(t)
	ts := newTestServer(Config{})
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/decrypt?password=wrong&password=Password1234_",
		"application/octet-stream", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var rep xcrack.Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Root.Format != "msoffice" {
		t.Fatalf("root format = %q, want msoffice", rep.Root.Format)
	}
	found := false
	for _, p := range rep.Passwords {
		if p == "Password1234_" {
			found = true
		}
	}
	if !found {
		t.Fatalf("recovered passwords = %v, want it to include Password1234_", rep.Passwords)
	}
}

func TestIdentifyDoesNotCrack(t *testing.T) {
	data := encryptedDoc(t)
	ts := newTestServer(Config{})
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/v1/identify", "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep xcrack.Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Root.Format != "msoffice" {
		t.Fatalf("root format = %q, want msoffice", rep.Root.Format)
	}
	if len(rep.Passwords) != 0 {
		t.Fatalf("identify recovered passwords %v; want none", rep.Passwords)
	}
	// At least one node must be locked (encrypted, no candidate tried).
	locked := false
	var walk func(n xcrack.NodeReport)
	walk = func(n xcrack.NodeReport) {
		if n.Status == "locked" {
			locked = true
		}
		for _, c := range n.Children {
			walk(c)
		}
	}
	walk(rep.Root)
	if !locked {
		t.Fatal("identify did not report any locked node")
	}
}

func TestWrongPasswordLocked(t *testing.T) {
	data := encryptedDoc(t)
	ts := newTestServer(Config{})
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/v1/decrypt?password=nope", "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep xcrack.Report
	json.NewDecoder(resp.Body).Decode(&rep)
	if len(rep.Passwords) != 0 {
		t.Fatalf("recovered %v with a wrong password", rep.Passwords)
	}
}

func TestBodyTooLarge(t *testing.T) {
	ts := newTestServer(Config{MaxBodyBytes: 16})
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/v1/decrypt", "application/octet-stream", strings.NewReader(strings.Repeat("A", 1024)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	ts := newTestServer(Config{})
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/v1/decrypt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
}

func TestDefaultListGated(t *testing.T) {
	data := encryptedDoc(t)
	ts := newTestServer(Config{}) // AllowDefaultList false
	defer ts.Close()
	resp, err := http.Post(ts.URL+"/v1/decrypt?defaults=true", "application/octet-stream", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (default list disabled)", resp.StatusCode)
	}
}
