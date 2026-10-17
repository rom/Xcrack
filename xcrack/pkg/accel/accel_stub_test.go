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

// TestVendorArch classifies vendor strings across GPU families.
func TestVendorArch(t *testing.T) {
	cases := map[string]string{
		"NVIDIA Corporation":           "NVIDIA",
		"Advanced Micro Devices, Inc.": "AMD",
		"AMD":                          "AMD",
		"Intel(R) Corporation":         "Intel",
		"Apple":                        "Apple",
		"Mesa/X.org":                   "Mesa",
		"The pocl project":             "pocl",
		"Some Other Vendor":            "Other",
	}
	for in, want := range cases {
		if got := VendorArch(in); got != want {
			t.Errorf("VendorArch(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestDeviceRank orders discrete GPU > integrated GPU/APU > accelerator > CPU.
func TestDeviceRank(t *testing.T) {
	discrete := Device{Type: "GPU", ComputeUnits: 60}
	apu := Device{Type: "GPU", ComputeUnits: 16, UnifiedMem: true}
	accelr := Device{Type: "ACCELERATOR", ComputeUnits: 8}
	cpu := Device{Type: "CPU", ComputeUnits: 32}
	if !(DeviceRank(discrete) > DeviceRank(apu) && DeviceRank(apu) > DeviceRank(accelr) && DeviceRank(accelr) > DeviceRank(cpu)) {
		t.Errorf("ranking wrong: discrete=%d apu=%d accel=%d cpu=%d",
			DeviceRank(discrete), DeviceRank(apu), DeviceRank(accelr), DeviceRank(cpu))
	}
}
