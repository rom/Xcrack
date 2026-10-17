// Command xcrackd runs the Xcrack recovery engine as an HTTP service.
//
// It is intended to run on a hardened backend host (optionally fronting a
// GPU/OpenCL cracking tier) and be called by clients such as an Impex kiosk or
// an Impex DataLock appliance. The service ships no authentication; run it
// behind a reverse proxy / mesh that provides authn/z, and never expose it
// directly to untrusted networks.
//
// Logging is an audit trail: every request that completes emits a structured
// record (client address, endpoint, bytes, elapsed) and, for each file that was
// successfully cracked, an entry with the filename, file type and time-to-crack.
// The record can go to stderr, a file, or the system logger (--syslog), in text
// or JSON. The recovered password is logged only with --audit-log-password.
package main

import (
	"context"
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
		readTimeout   = flag.Duration("read-timeout", 30*time.Second, "HTTP read timeout")
		writeTimeout  = flag.Duration("write-timeout", 150*time.Second, "HTTP write timeout")
		shutdownGrace = flag.Duration("shutdown-grace", 20*time.Second, "graceful shutdown grace period")
		gpu           = flag.Bool("gpu", false, "enable the optional OpenCL GPU acceleration tier (requires a binary built with -tags opencl on a host with OpenCL hardware; the default build is pure-Go)")
		gpuSelfTest   = flag.Bool("gpu-selftest", false, "validate the OpenCL PBKDF2 kernel against the CPU reference and exit (requires -tags opencl)")
		dualPipeline  = flag.Bool("dual-pipeline", false, "dual CPU+GPU pipeline: race the CPU search and the GPU sweep over one shared keyspace per file, first to find wins (needs --gpu; the CPU no longer sits idle while the device works)")

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
		} else if err := accel.GPUSelfTest(); err != nil {
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
	pool := xcrack.NewPool(xcrack.Options{
		Workers:         *workers,
		MaxProcs:        *maxProcs,
		FileConcurrency: *fileJobs,
		Accelerator:     gpuAcc,
		DualPipeline:    *dualPipeline,
		Logger:          auditlog.Printf(logger),
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

	httpSrv := &http.Server{
		Addr:         *addr,
		Handler:      srv.Handler(),
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  120 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("xcrackd listening", "addr", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
