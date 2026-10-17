//go:build !opencl

// This file is the default (pure-Go) backend: no cgo, no OpenCL dependency.
// Detect always reports that GPU support was not built in, so xcrackd runs the
// unchanged CPU engine.

package accel

const built = false

// Detect reports that no OpenCL backend is available in a pure-Go build.
func Detect() (Accelerator, error) { return nil, ErrNotBuilt }

// GPUSelfTest is a no-op in a pure-Go build.
func GPUSelfTest() error { return ErrNotBuilt }

// GPUSelfTestWith is a no-op in a pure-Go build.
func GPUSelfTestWith(Accelerator) error { return ErrNotBuilt }
