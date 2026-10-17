// Command xcrackd runs the Xcrack recovery engine as an HTTP service.
//
// It is intended to run on a hardened backend host (optionally fronting a
// GPU/OpenCL cracking tier) and be called by clients such as an Impex kiosk or
// an Impex DataLock appliance. The service ships no authentication or TLS; run
// it behind a reverse proxy / mesh that provides authn/z and transport security,
// and never expose it directly to untrusted networks.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrack/pkg/api"
	"github.com/rom/xcrack/pkg/xcrack"
)

func main() {
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
	)
	flag.Parse()

	// GPU self-test: prove the OpenCL kernel is byte-for-byte correct on this
	// host, then exit. Useful before enabling --gpu in production.
	if *gpuSelfTest {
		if err := accel.GPUSelfTest(); err != nil {
			log.Fatalf("GPU self-test FAILED: %v", err)
		}
		log.Printf("GPU self-test PASSED: OpenCL PBKDF2-HMAC-SHA1 matches the CPU reference")
		return
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
			log.Printf("--gpu requested but this binary is pure-Go; rebuild with -tags opencl. Continuing on CPU.")
		} else if acc, err := accel.Detect(); err != nil {
			log.Printf("--gpu requested but no usable OpenCL device: %v. Continuing on CPU.", err)
		} else if err := accel.GPUSelfTest(); err != nil {
			log.Printf("GPU self-test failed (%v); not using the GPU tier. Continuing on CPU.", err)
			acc.Close()
		} else {
			gpuAcc = acc
			defer acc.Close()
			for _, d := range acc.Devices() {
				kind := d.Type
				if d.UnifiedMem && d.Type == "GPU" {
					kind = "GPU/APU"
				}
				log.Printf("GPU tier: [%s] %s %s (%s, %d compute units)", accel.VendorArch(d.Vendor), d.Vendor, d.Name, kind, d.ComputeUnits)
			}
			msg := fmt.Sprintf("GPU tier: PBKDF2-HMAC-SHA1/SHA256/SHA512 kernels validated and active across %d device(s)", len(acc.Devices()))
			if bt, ok := acc.(accel.BatchTuner); ok {
				msg += fmt.Sprintf("; autotuned batch %d", bt.OptimalBatch())
			}
			log.Print(msg)
		}
	}

	pool := xcrack.NewPool(xcrack.Options{
		Workers:         *workers,
		MaxProcs:        *maxProcs,
		FileConcurrency: *fileJobs,
		Accelerator:     gpuAcc,
	})
	defer pool.Close()

	srv := api.NewServer(pool, api.Config{
		MaxBodyBytes:     *maxBody,
		RequestTimeout:   *reqTimeout,
		AllowDefaultList: *allowDefaults,
	})

	httpSrv := &http.Server{
		Addr:         *addr,
		Handler:      srv.Handler(),
		ReadTimeout:  *readTimeout,
		WriteTimeout: *writeTimeout,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("xcrackd listening on %s", *addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), *shutdownGrace)
	defer cancel()
	if err := httpSrv.Shutdown(ctx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
		os.Exit(1)
	}
}
