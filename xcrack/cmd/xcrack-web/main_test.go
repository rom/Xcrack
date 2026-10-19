package main

import (
	"crypto/tls"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/rom/xcrack/pkg/securecache"
)

func TestServerTLSConfig(t *testing.T) {
	if c, err := serverTLSConfig("1.2", ""); err != nil || c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("1.2 => %v, %v", c, err)
	}
	if c, err := serverTLSConfig("1.3", ""); err != nil || c.MinVersion != tls.VersionTLS13 {
		t.Fatalf("1.3 => %v, %v", c, err)
	}
	if _, err := serverTLSConfig("1.1", ""); err == nil {
		t.Fatal("expected an error for an unsupported TLS version")
	}
	if _, err := serverTLSConfig("1.2", filepath.Join(t.TempDir(), "nope.pem")); err == nil {
		t.Fatal("expected an error for a missing client CA file")
	}
}

func TestResolveDocsDir(t *testing.T) {
	if got := resolveDocsDir("/explicit/path"); got != "/explicit/path" {
		t.Errorf("explicit docs-dir = %q, want it honoured", got)
	}
	dir := t.TempDir()
	if hasMarkdown(dir) {
		t.Fatal("empty dir should have no markdown")
	}
	if err := os.WriteFile(filepath.Join(dir, "a.md"), []byte("# x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasMarkdown(dir) {
		t.Fatal("dir with a .md should be detected")
	}
}

func TestResolveAuthMode(t *testing.T) {
	cases := []struct {
		name                             string
		mode, issuer, client, redir, adm string
		wantEnabled, wantErr             bool
	}{
		{name: "single default", mode: "single", wantEnabled: false},
		{name: "single rejects issuer", mode: "single", issuer: "https://idp", wantErr: true},
		{name: "single rejects admins", mode: "single", adm: "a@b", wantErr: true},
		{name: "multi full config", mode: "multi", issuer: "https://idp", client: "cid", redir: "https://host/auth/callback", wantEnabled: true},
		{name: "multi needs issuer", mode: "multi", wantEnabled: true, wantErr: true},
		{name: "multi needs client+redirect", mode: "multi", issuer: "https://idp", wantEnabled: true, wantErr: true},
		{name: "unknown mode", mode: "both", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enabled, err := resolveAuthMode(c.mode, c.issuer, c.client, c.redir, c.adm)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
			}
			if enabled != c.wantEnabled {
				t.Errorf("enabled = %v, want %v", enabled, c.wantEnabled)
			}
		})
	}
}

func TestGPUAcceleratorPureGo(t *testing.T) {
	// In the default (pure-Go) build the hook must report ok=false so jobs run on
	// the CPU rather than failing.
	hook := gpuAccelerator(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	acc, closer, ok := hook(nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if ok || acc != nil || closer != nil {
		t.Fatalf("pure-Go GPU hook = (acc=%v, closer!=nil=%v, ok=%v), want (nil,nil,false)", acc, closer != nil, ok)
	}
	if securecache.TPMBuilt {
		t.Error("securecache.TPMBuilt should be false in the default build")
	}
}
