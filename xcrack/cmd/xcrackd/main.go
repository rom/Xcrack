// Command xcrackd runs the Xcrack recovery engine as an HTTP service.
//
// It is intended to run on a hardened backend host (optionally fronting a
// GPU/OpenCL cracking tier) and be called by clients such as an Impex kiosk or
// an Impex DataLock appliance. It can terminate TLS itself (--tls-cert/--tls-key,
// with optional mutual-TLS client-certificate verification via --tls-client-ca;
// see scripts/gen-selfsigned-cert.sh and scripts/gen-letsencrypt-cert.sh), or run
// plaintext behind a TLS-terminating reverse proxy / mesh. It ships no
// authentication, so put authn/z in front of it and never expose it directly to
// untrusted networks.
//
// Logging is an audit trail: every request that completes emits a structured
// record (client address, endpoint, bytes, elapsed) and, for each file that was
// successfully cracked, an entry with the filename, file type and time-to-crack.
// The record can go to stderr, a file, or the system logger (--syslog), in text
// or JSON. The recovered password is logged only with --audit-log-password.
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
	"syscall"
	"time"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrack/pkg/api"
	"github.com/rom/xcrack/pkg/auditlog"
	"github.com/rom/xcrack/pkg/xcrack"
)

func main() {
	os.Exit(run())
}

func run() int {
	var (
		addr          = flag.String("addr", ":8080", "listen address")
		workers       = flag.Int("workers", 0, "candidate-test goroutines per file (0=NumCPU)")
		maxProcs      = flag.Int("max-procs", 0, "global ceiling on concurrent candidate testers (0=NumCPU)")
		fileJobs      = flag.Int("file-jobs", 0, "container entries processed concurrently (0=NumCPU)")
		maxBody       = flag.Int64("max-body", 256<<20, "maximum request body size in bytes")
		reqTimeout    = flag.Duration("request-timeout", 120*time.Second, "per-request processing deadline")
		allowDefaults = flag.Bool("allow-default-list", false, "allow ?defaults=true to use the embedded wordlist")

		// Engine knobs (match the CLI's — the server configures the same engine).
		batchSize    = flag.Int("batch-size", 0, "candidates per worker hand-off (0=auto)")
		throttle     = flag.Int("throttle", 0, "approximate CPU duty cycle percent 1..99 (0=off)")
		noRecurse    = flag.Bool("no-recurse", false, "disable container decomposition (treat each upload as a single target)")
		explode      = flag.Bool("explode-documents", false, "decompose documents into their internal parts")
		contextCands = flag.Bool("context", false, "seed guesses from the node name and plaintext harvested from plain sibling entries")
		hintCands    = flag.Bool("hint", false, "derive guesses from a file's embedded password hint (iWork .iwph, ZIP comment)")
		maxDepth     = flag.Int("max-depth", 0, "max nesting depth (0=default)")
		maxNodes     = flag.Int("max-nodes", 0, "max extracted entries (0=default)")
		maxTotal     = flag.Int64("max-total-bytes", 0, "cumulative decompressed byte budget (0=default)")
		maxEntry     = flag.Int64("max-entry-size", 0, "max single-entry size (0=default)")
		maxCand      = flag.Int64("max-candidates", 0, "max candidates tested per encrypted node (0=unlimited)")

		readTimeout   = flag.Duration("read-timeout", 30*time.Second, "HTTP read timeout")
		writeTimeout  = flag.Duration("write-timeout", 150*time.Second, "HTTP write timeout")
		shutdownGrace = flag.Duration("shutdown-grace", 20*time.Second, "graceful shutdown grace period")
		gpu           = flag.Bool("gpu", false, "enable the optional OpenCL GPU acceleration tier (requires a binary built with -tags opencl on a host with OpenCL hardware; the default build is pure-Go)")
		gpuSelfTest   = flag.Bool("gpu-selftest", false, "validate the OpenCL PBKDF2 kernel against the CPU reference and exit (requires -tags opencl)")
		dualPipeline  = flag.Bool("dual-pipeline", false, "dual CPU+GPU pipeline: race the CPU search and the GPU sweep over one shared keyspace per file, first to find wins (needs --gpu; the CPU no longer sits idle while the device works)")

		tlsCert     = flag.String("tls-cert", "", "serve HTTPS with this PEM certificate chain (requires --tls-key; see scripts/gen-selfsigned-cert.sh and scripts/gen-letsencrypt-cert.sh)")
		tlsKey      = flag.String("tls-key", "", "private key (PEM) for --tls-cert")
		tlsClientCA = flag.String("tls-client-ca", "", "require and verify client certificates against this PEM CA bundle (mutual TLS); empty disables client-cert auth")
		tlsMinVer   = flag.String("tls-min-version", "1.2", "minimum TLS version: 1.2 or 1.3")

		logLevel      = flag.String("log-level", "info", "log level: debug|info|warn|error")
		logFormat     = flag.String("log-format", "text", "log/audit output format: text|json")
		logFile       = flag.String("log-file", "", "append the structured log + audit trail to this file (default: stderr)")
		syslogF       = flag.Bool("syslog", false, "send the log + audit trail to the system logger (syslog) instead of stderr")
		syslogAddr    = flag.String("syslog-address", "", "remote syslog host:port (with --syslog; empty uses the local syslog socket)")
		syslogNet     = flag.String("syslog-network", "", "remote syslog transport udp|tcp (with --syslog-address)")
		syslogTag     = flag.String("syslog-tag", "xcrackd", "syslog tag/ident (with --syslog)")
		auditPassword = flag.Bool("audit-log-password", false, "include the recovered password in the audit log entry for a cracked file (off by default so the trail stays secrets-free)")
	)
	flag.Parse()

	logger, logCloser, err := auditlog.New(auditlog.Config{
		Level:          *logLevel,
		Format:         *logFormat,
		File:           *logFile,
		Syslog:         *syslogF,
		SyslogNetwork:  *syslogNet,
		SyslogAddress:  *syslogAddr,
		SyslogTag:      *syslogTag,
		IncludeSecrets: *auditPassword,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "xcrackd: logging: %v\n", err)
		return 1
	}
	defer logCloser.Close()

	// GPU self-test: prove the OpenCL kernel is byte-for-byte correct on this
	// host, then exit. Useful before enabling --gpu in production.
	if *gpuSelfTest {
		if err := accel.GPUSelfTest(); err != nil {
			logger.Error("GPU self-test FAILED", "err", err)
			return 1
		}
		logger.Info("GPU self-test PASSED: OpenCL PBKDF2-HMAC-SHA1 matches the CPU reference")
		return 0
	}

	// Optional GPU tier. It is opt-in and hardware-gated: without an -tags opencl
	// build, or without OpenCL hardware, xcrackd logs why and runs the unchanged
	// pure-Go CPU engine. When a device is present and the kernel self-test
	// passes, the accelerator is handed to the engine (Options.Accelerator), which
	// offloads the shared PBKDF2-HMAC-SHA1 sweep of acceleration-capable targets
	// (WinZip-AES, DMG, ...) to it and keeps the CPU path for everything else.
	var gpuAcc accel.Accelerator
	if *gpu {
		if !accel.Built() {
			logger.Warn("--gpu requested but this binary is pure-Go; rebuild with -tags opencl. Continuing on CPU.")
		} else if acc, err := accel.Detect(); err != nil {
			logger.Warn("--gpu requested but no usable OpenCL device; continuing on CPU", "err", err)
		} else if err := accel.GPUSelfTestWith(acc); err != nil {
			// Validate the context we just opened (the one handed to the engine
			// below) instead of opening a second one, so device/kernel init is
			// paid once and the proven context is the one actually used.
			logger.Warn("GPU self-test failed; not using the GPU tier, continuing on CPU", "err", err)
			acc.Close()
		} else {
			gpuAcc = acc
			defer acc.Close()
			for _, d := range acc.Devices() {
				kind := d.Type
				if d.UnifiedMem && d.Type == "GPU" {
					kind = "GPU/APU"
				}
				logger.Info("GPU tier device",
					"arch", accel.VendorArch(d.Vendor), "vendor", d.Vendor, "name", d.Name,
					"kind", kind, "compute_units", d.ComputeUnits)
			}
			msg := fmt.Sprintf("GPU tier: PBKDF2-HMAC-SHA1/SHA256/SHA512 kernels validated and active across %d device(s)", len(acc.Devices()))
			if bt, ok := acc.(accel.BatchTuner); ok {
				msg += fmt.Sprintf("; autotuned batch %d", bt.OptimalBatch())
			}
			logger.Info(msg)
		}
	}

	if *dualPipeline && gpuAcc == nil {
		logger.Warn("--dual-pipeline has no effect without an active GPU tier; running the CPU search alone")
	}

	// Engine limits: start from the safe defaults and override only what the
	// operator set (0 keeps the default floor; normalize() re-applies floors).
	limits := xcrack.DefaultLimits()
	if *maxDepth > 0 {
		limits.MaxDepth = *maxDepth
	}
	if *maxNodes > 0 {
		limits.MaxNodes = *maxNodes
	}
	if *maxTotal > 0 {
		limits.MaxTotalBytes = *maxTotal
	}
	if *maxEntry > 0 {
		limits.MaxEntrySize = *maxEntry
	}
	limits.MaxCandidates = *maxCand

	pool := xcrack.NewPool(xcrack.Options{
		Workers:           *workers,
		MaxProcs:          *maxProcs,
		FileConcurrency:   *fileJobs,
		BatchSize:         *batchSize,
		ThrottlePercent:   *throttle,
		NoRecurse:         *noRecurse,
		ExplodeDocuments:  *explode,
		ContextCandidates: *contextCands,
		HintCandidates:    *hintCands,
		Limits:            limits,
		Accelerator:       gpuAcc,
		DualPipeline:      *dualPipeline,
		Logger:            auditlog.Printf(logger),
	})
	defer pool.Close()

	srv := api.NewServer(pool, api.Config{
		MaxBodyBytes:     *maxBody,
		RequestTimeout:   *reqTimeout,
		AllowDefaultList: *allowDefaults,
		// Per-request audit trail: one "request served" summary plus a "file
		// cracked" entry (filename, file type, time-to-crack, optionally the
		// password) for every recovery, all tagged with the client and endpoint.
		Audit: func(res *xcrack.Result, meta api.AuditMeta) {
			clientAttrs := []slog.Attr{
				slog.String("client", meta.RemoteAddr),
				slog.String("endpoint", meta.Endpoint),
			}
			auditlog.LogFile(logger, "", res, *auditPassword, clientAttrs...)
			logger.LogAttrs(context.Background(), slog.LevelInfo, "request served",
				slog.String("client", meta.RemoteAddr),
				slog.String("endpoint", meta.Endpoint),
				slog.Int("bytes", meta.Bytes),
				slog.String("elapsed", meta.Elapsed.Round(time.Millisecond).String()),
			)
		},
	})

	// TLS: when a certificate/key pair is configured, serve HTTPS with a hardened
	// config (TLS 1.2+ floor, optional mutual-TLS client-cert verification). The
	// cert/key are loaded by ListenAndServeTLS; the rest comes from TLSConfig.
	tlsEnabled := *tlsCert != "" || *tlsKey != ""
	var tlsConf *tls.Config
	if tlsEnabled {
		if *tlsCert == "" || *tlsKey == "" {
			fmt.Fprintln(os.Stderr, "xcrackd: --tls-cert and --tls-key must be given together")
			return 1
		}
		c, err := serverTLSConfig(*tlsMinVer, *tlsClientCA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "xcrackd: tls: %v\n", err)
			return 1
		}
		tlsConf = c
	}

	httpSrv := &http.Server{
		Addr:         *addr,
		Handler:      srv.Handler(),
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  120 * time.Second,
		TLSConfig:    tlsConf,
	}

	serveErr := make(chan error, 1)
	go func() {
		scheme := "http"
		if tlsEnabled {
			scheme = "https"
		}
		logger.Info("xcrackd listening", "addr", *addr, "scheme", scheme, "mutual_tls", tlsConf != nil && tlsConf.ClientAuth == tls.RequireAndVerifyClientCert)
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
	if err := httpSrv.Shutdown(ctx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		return 1
	}
	return 0
}

// serverTLSConfig builds the server's TLS configuration: a minimum-version floor
// (TLS 1.2 or 1.3) and, when clientCAFile is set, mutual TLS — client
// certificates are required and verified against that PEM CA bundle. The server
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
