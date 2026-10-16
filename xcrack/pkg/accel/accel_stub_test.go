//go:build !opencl

package accel

import (
	"errors"
	"testing"
)

// TestDefaultBuildHasNoGPU asserts the pure-Go default build advertises no GPU
// support and both entry points report ErrNotBuilt, so nothing silently depends
// on cgo/OpenCL.
func TestDefaultBuildHasNoGPU(t *testing.T) {
	if Built() {
		t.Error("Built() = true in a default (pure-Go) build")
	}
	if _, err := Detect(); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("Detect() err = %v, want ErrNotBuilt", err)
	}
	if err := GPUSelfTest(); !errors.Is(err, ErrNotBuilt) {
		t.Errorf("GPUSelfTest() err = %v, want ErrNotBuilt", err)
	}
}
