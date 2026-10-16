// Package accel is the optional, server-tier GPU/OpenCL acceleration seam for
// xcrackd. It is the one sanctioned exception to ADR 0001 (pure-Go, no cgo):
// the default build stays pure-Go and cgo-free, and an OpenCL backend is
// compiled in ONLY with `-tags opencl` and used ONLY when the host has OpenCL
// hardware. A server operator opts in explicitly; everyone else gets the
// unchanged CPU engine, and CI never builds or runs the GPU path.
//
// The acceleration is deliberately scoped to the heavy, embarrassingly-parallel
// primitive the password schemes share — PBKDF2-HMAC-SHA1 key derivation (used
// by WinZip-AES, encrypted DMG, ODF, SQLCipher) — exposed as a batch call.
// Everything else (format parsing, verification, recursion) stays on the CPU in
// pure Go. The GPU output is always byte-for-byte identical to the Go reference
// (prim.PBKDF2), so a GPU result is never trusted blindly: it is validated at
// startup (GPUSelfTest) against the reference before use.
package accel

import "errors"

// ErrNotBuilt is returned by Detect in a default (pure-Go) build: no OpenCL
// backend was compiled in.
var ErrNotBuilt = errors.New("accel: GPU/OpenCL support not built (rebuild xcrackd with -tags opencl)")

// ErrUnsupported is returned by an Accelerator for an operation its backend has
// no kernel for; the caller falls back to the CPU engine.
var ErrUnsupported = errors.New("accel: operation not supported by this backend")

// Device describes one OpenCL compute device.
type Device struct {
	Platform     string
	Name         string
	Vendor       string
	Type         string // "GPU", "CPU", "ACCELERATOR", or "OTHER"
	ComputeUnits int
}

// Accelerator is a ready OpenCL context over one or more devices. It is created
// by Detect (only in an -tags opencl build) and released with Close.
type Accelerator interface {
	// Devices lists the backing compute devices.
	Devices() []Device
	// PBKDF2SHA1 derives a dkLen-byte key for each password against the shared
	// salt and iteration count, on the device. It returns ErrUnsupported if the
	// backend has no kernel for these parameters, so the caller can fall back to
	// the CPU. Results are in input order.
	PBKDF2SHA1(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error)
	// Close releases the context.
	Close() error
}

// Built reports whether an OpenCL backend was compiled into this binary. It is
// false for the default pure-Go build.
func Built() bool { return built }
