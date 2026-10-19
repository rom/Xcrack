// Command xcrack-web serves the Xcrack recovery engine as a browser
// application: a single-page GUI plus a JSON/SSE API exposing the full engine
// feature set (see pkg/webui).
//
// It runs in one of two modes, chosen with --mode:
//
//   - single (the default): a no-login, single-user recovery console. Every
//     request is the implicit local owner. This is the localhost default and
//     needs no identity provider.
//   - multi: a shared service with per-user job ownership, fronted by an OIDC
//     identity provider (--auth-oidc-* flags). Each user sees only their own
//     jobs; --auth-admins may see everyone's.
//
// Single-user mode ships no authentication, so a non-localhost single-user
// instance MUST sit behind an authenticating proxy. Either mode, when reachable
// off-host, MUST have transport security — xcrack-web's own TLS (--tls-cert/
// --tls-key) or a terminating proxy; never expose it directly to an untrusted
// network. A submitted job may reference only files uploaded with it unless
// --allow-server-paths is set.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrack/pkg/jobspec"
	"github.com/rom/xcrack/pkg/securecache"
	"github.com/rom/xcrack/pkg/webui"
	"github.com/rom/xcrack/pkg/xcrack"
)

const version = "0.1.0-mvp"

func main() { os.Exit(run()) }

func run() int {
	var (
		addr          = flag.String("addr", "127.0.0.1:8899", "listen address (default localhost only; use :PORT to listen on all interfaces)")
		workDir       = flag.String("work-dir", "", "root for per-job working directories (default: <temp>/xcrack-web)")
		docsDir       = flag.String("docs-dir", "", "directory of Markdown docs to serve in the app (default: auto-detect ./docs)")
		maxUpload     = flag.Int64("max-upload", 512<<20, "maximum job-submission size in bytes")
		maxJobs       = flag.Int("max-jobs", 0, "maximum jobs running at once (0 = unlimited); extra jobs stay queued")
		exposeSecrets = flag.Bool("expose-secrets", true, "show recovered passwords in the UI and event stream (turn OFF for a shared/public instance)")
		allowPaths    = flag.Bool("allow-server-paths", false, "allow a submitted spec to reference server-side file paths, not just uploaded files (trusted local instance only)")
		open          = flag.Bool("print-url", true, "print the URL to open on startup")

		tlsCert     = flag.String("tls-cert", "", "serve HTTPS with this PEM certificate chain (requires --tls-key; see scripts/gen-selfsigned-cert.sh)")
		tlsKey      = flag.String("tls-key", "", "private key (PEM) for --tls-cert")
		tlsClientCA = flag.String("tls-client-ca", "", "require and verify client certificates against this PEM CA bundle (mutual TLS)")
		tlsMinVer   = flag.String("tls-min-version", "1.2", "minimum TLS version: 1.2 or 1.3")

		shutdownGrace = flag.Duration("shutdown-grace", 10*time.Second, "graceful shutdown grace period")

		mode = flag.String("mode", "single", "run mode: 'single' (no login, single-user console) or 'multi' (per-user access; requires the --auth-oidc-* flags)")

		oidcIssuer   = flag.String("auth-oidc-issuer", "", "multi-user OIDC issuer URL, read with --mode multi (its /.well-known/openid-configuration is fetched at startup)")
		oidcClientID = flag.String("auth-oidc-client-id", "", "OIDC client ID (required with --auth-oidc-issuer)")
		oidcRedirect = flag.String("auth-redirect-url", "", "this server's own /auth/callback URL as registered with the provider, e.g. https://host:8899/auth/callback (required with --auth-oidc-issuer)")
		authAdmins   = flag.String("auth-admins", "", "comma-separated subjects or emails allowed to see and manage every user's jobs")
		cookieInsec  = flag.Bool("auth-cookie-insecure", false, "do not set the Secure flag on the session cookie (plain-HTTP local testing only)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// The OIDC client secret comes from the environment, never argv (process
	// arguments are world-readable on many systems).
	clientSecret := os.Getenv("XCRACK_WEB_OIDC_CLIENT_SECRET")

	// Resolve single- vs multi-user up front: --mode is the explicit switch, and a
	// misconfigured provider must never silently leave the console open.
	authEnabled, err := resolveAuthMode(*mode, *oidcIssuer, *oidcClientID, *oidcRedirect, *authAdmins)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack-web: %v\n", err)
		return 1
	}

	cfg := webui.Config{
		WorkDir:           *workDir,
		DocsDir:           resolveDocsDir(*docsDir),
		MaxUploadBytes:    *maxUpload,
		MaxConcurrentJobs: *maxJobs,
		ExposeSecrets:     *exposeSecrets,
		AllowServerPaths:  *allowPaths,
		GPUAvailable:      accel.Built(),
		TPMBuild:          securecache.TPMBuilt,
		Version:           version,
		TLS:               *tlsCert != "" || *tlsKey != "",
		Accelerator:       gpuAccelerator(logger),
		Auth: webui.AuthConfig{
			Enabled:      authEnabled,
			Issuer:       *oidcIssuer,
			ClientID:     *oidcClientID,
			ClientSecret: clientSecret,
			RedirectURL:  *oidcRedirect,
			Admins:       splitComma(*authAdmins),
			CookieSecure: !*cookieInsec,
		},
	}
	if cfg.Auth.Enabled {
		logger.Info("multi-user mode", "issuer", cfg.Auth.Issuer, "admins", len(cfg.Auth.Admins))
	} else {
		logger.Info("single-user mode (no login)")
	}

	srv, err := webui.NewServer(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrack-web: %v\n", err)
		return 1
	}

	tlsEnabled := *tlsCert != "" || *tlsKey != ""
	var tlsConf *tls.Config
	if tlsEnabled {
		if *tlsCert == "" || *tlsKey == "" {
			fmt.Fprintln(os.Stderr, "xcrack-web: --tls-cert and --tls-key must be given together")
			return 1
		}
		c, err := serverTLSConfig(*tlsMinVer, *tlsClientCA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrack-web: tls: %v\n", err)
			return 1
		}
		tlsConf = c
	}

	httpSrv := &http.Server{
		Addr:    *addr,
		Handler: srv.Handler(),
		// No Read/Write timeouts: uploads can be large and the SSE event stream is
		// long-lived. ReadHeaderTimeout still bounds slow-header (slowloris) clients.
		ReadHeaderTimeout: 20 * time.Second,
		IdleTimeout:       120 * time.Second,
		TLSConfig:         tlsConf,
	}

	scheme := "http"
	if tlsEnabled {
		scheme = "https"
	}
	if *open {
		host := *addr
		if strings.HasPrefix(host, ":") {
			host = "localhost" + host
		} else if strings.HasPrefix(host, "0.0.0.0:") {
			host = "localhost" + strings.TrimPrefix(host, "0.0.0.0")
		}
		fmt.Printf("xcrack-web: open %s://%s\n", scheme, host)
	}
	warnIfPublic(*addr, *exposeSecrets, tlsEnabled, logger)

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("xcrack-web listening", "addr", *addr, "scheme", scheme,
			"gpu", accel.Built(), "tpm", securecache.TPMBuilt, "expose_secrets", *exposeSecrets)
		var err error
		if tlsEnabled {
			err = httpSrv.ListenAndServeTLS(*tlsCert, *tlsKey)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-serveErr:
		logger.Error("server error", "err", err)
		return 1
	case <-stop:
	}
	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), *shutdownGrace)
	defer cancel()
	err = httpSrv.Shutdown(ctx)
	// Stop accepting requests first (above), then cancel and await in-flight job
	// runners so they are not abandoned mid-write on exit. Done even if the HTTP
	// shutdown timed out.
	srv.Close()
	if err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		return 1
	}
	return 0
}

// resolveAuthMode validates the --mode selection against the OIDC flags and
// reports whether multi-user auth should be enabled.
//
//   - "single" (the default) is a no-login, single-user console. It rejects stray
//     --auth-* flags so a half-configured provider can never silently leave the
//     console open to everyone.
//   - "multi" turns on per-user access and requires an OIDC issuer, client ID, and
//     redirect URL (the client secret is read from the environment separately).
func resolveAuthMode(mode, issuer, clientID, redirect, admins string) (enabled bool, err error) {
	switch mode {
	case "single":
		if issuer != "" || clientID != "" || redirect != "" || admins != "" {
			return false, fmt.Errorf("--mode single takes no --auth-* flags; pass --mode multi for multi-user login, or drop the --auth-oidc-* / --auth-admins flags")
		}
		return false, nil
	case "multi":
		if issuer == "" {
			return true, fmt.Errorf("--mode multi requires --auth-oidc-issuer (plus --auth-oidc-client-id and --auth-redirect-url)")
		}
		if clientID == "" || redirect == "" {
			return true, fmt.Errorf("--mode multi requires --auth-oidc-client-id and --auth-redirect-url")
		}
		return true, nil
	default:
		return false, fmt.Errorf("--mode must be 'single' or 'multi', got %q", mode)
	}
}

// splitComma splits a comma-separated flag value into trimmed, non-empty parts.
func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// gpuAccelerator returns the webui GPU hook. In a pure-Go build accel.Built() is
// false and the hook reports ok=false so jobs run on the CPU. With a -tags
// opencl build on GPU hardware it opens a device, validates the kernel against
// the CPU reference, and hands the accelerator to the job (closed when done).
func gpuAccelerator(logger *slog.Logger) func(*jobspec.Spec, *slog.Logger) (xcrack.Accelerator, func(), bool) {
	return func(_ *jobspec.Spec, jobLog *slog.Logger) (xcrack.Accelerator, func(), bool) {
		if !accel.Built() {
			jobLog.Warn("GPU requested but this binary is pure-Go; rebuild with -tags opencl. Running on CPU.")
			return nil, nil, false
		}
		acc, err := accel.Detect()
		if err != nil {
			jobLog.Warn("GPU requested but no usable OpenCL device; running on CPU", "err", err)
			return nil, nil, false
		}
		if err := accel.GPUSelfTestWith(acc); err != nil {
			jobLog.Warn("GPU self-test failed; running on CPU", "err", err)
			acc.Close()
			return nil, nil, false
		}
		jobLog.Info("GPU tier active", "devices", len(acc.Devices()))
		return acc, func() { acc.Close() }, true
	}
}

// resolveDocsDir honours an explicit --docs-dir, else auto-detects a docs
// directory next to the working directory so the in-app manual is available
// without configuration. It returns "" when none is found (the built-in quick
// start is still served).
func resolveDocsDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	for _, c := range []string{"docs", filepath.Join("..", "docs"), filepath.Join("..", "..", "docs"), "/usr/share/xcrack/docs"} {
		if hasMarkdown(c) {
			return c
		}
	}
	return ""
}

func hasMarkdown(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(strings.ToLower(e.Name()), ".md") {
			return true
		}
	}
	return false
}

// warnIfPublic warns when the server is reachable off-host without the
// protections a shared instance needs.
func warnIfPublic(addr string, exposeSecrets, tlsEnabled bool, logger *slog.Logger) {
	local := strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "localhost:") || strings.HasPrefix(addr, "[::1]:")
	if local {
		return
	}
	logger.Warn("xcrack-web is listening on a non-localhost address and ships NO authentication; put it behind an authenticating proxy", "addr", addr)
	if !tlsEnabled {
		logger.Warn("TLS is not enabled (--tls-cert/--tls-key); traffic, uploads and recovered secrets are in cleartext")
	}
	if exposeSecrets {
		logger.Warn("recovered passwords are exposed in the UI/event stream (--expose-secrets); pass --expose-secrets=false for a shared instance")
	}
}

// serverTLSConfig builds the server's TLS configuration: a minimum-version floor
// (TLS 1.2 or 1.3) and, when clientCAFile is set, mutual TLS. The server
// certificate itself is loaded from the files by ListenAndServeTLS.
func serverTLSConfig(minVer, clientCAFile string) (*tls.Config, error) {
	conf := &tls.Config{}
	switch minVer {
	case "", "1.2":
		conf.MinVersion = tls.VersionTLS12
	case "1.3":
		conf.MinVersion = tls.VersionTLS13
	default:
		return nil, fmt.Errorf("--tls-min-version must be 1.2 or 1.3, got %q", minVer)
	}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("client CA %q contained no PEM certificates", clientCAFile)
		}
		conf.ClientCAs = pool
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return conf, nil
}
