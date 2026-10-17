package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// tlsClientOpts configures TLS for the distributed-mode HTTP client that talks
// to https:// xcrackd servers.
type tlsClientOpts struct {
	CAFile     string // PEM CA bundle to verify the server cert (private CA / self-signed)
	CertFile   string // client certificate (PEM) for mutual TLS
	KeyFile    string // private key (PEM) for CertFile
	ServerName string // expected server cert name (SNI / verification override)
	Insecure   bool   // skip server verification (INSECURE — testing only)
}

// buildClusterHTTPClient returns the *http.Client the cluster orchestrator uses
// to reach the xcrackd servers, configured for TLS from the flags (falling back
// to the config file's cluster.tls block). With no TLS settings it returns a
// plain client that uses the system trust store for https:// (and plain HTTP for
// http://), identical to the previous default.
func buildClusterHTTPClient(o tlsClientOpts, cfg *fileConfig) (*http.Client, error) {
	// Config fallbacks: a flag wins, else the config value.
	if cfg != nil {
		t := cfg.Cluster.TLS
		o.CAFile = firstNonEmpty(o.CAFile, t.CA)
		o.CertFile = firstNonEmpty(o.CertFile, t.Cert)
		o.KeyFile = firstNonEmpty(o.KeyFile, t.Key)
		o.ServerName = firstNonEmpty(o.ServerName, t.ServerName)
		if !o.Insecure {
			o.Insecure = t.Insecure
		}
	}

	if o.CAFile == "" && o.CertFile == "" && o.KeyFile == "" && o.ServerName == "" && !o.Insecure {
		return &http.Client{}, nil // system defaults; nothing to customize
	}

	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read --tls-ca: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--tls-ca %q contained no PEM certificates", o.CAFile)
		}
		conf.RootCAs = pool
	}
	if o.CertFile != "" || o.KeyFile != "" {
		if o.CertFile == "" || o.KeyFile == "" {
			return nil, fmt.Errorf("--tls-cert and --tls-key must be given together")
		}
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client certificate: %w", err)
		}
		conf.Certificates = []tls.Certificate{cert}
	}
	if o.ServerName != "" {
		conf.ServerName = o.ServerName
	}
	if o.Insecure {
		conf.InsecureSkipVerify = true //nolint:gosec // opt-in, documented testing-only escape hatch
	}

	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = conf
	return &http.Client{Transport: tr}, nil
}
