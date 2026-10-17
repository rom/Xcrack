package main

import (
	"fmt"
	"log/slog"

	"github.com/rom/xcrack/pkg/accel"
	"github.com/rom/xcrack/pkg/xcrack"
)

// enableGPU attaches an OpenCL accelerator to opts for the live crack loop when
// one is available, and returns a cleanup func (always safe to call). It mirrors
// xcrackd's --gpu handling: the default pure-Go build has no backend, and a
// missing device or a failed kernel self-test degrades transparently to the CPU
// — so --gpu never fails a run, it only logs why it could not accelerate.
func enableGPU(opts *xcrack.Options, logger *slog.Logger) (cleanup func()) {
	noop := func() {}
	if !accel.Built() {
		logger.Warn("--gpu requested but this binary is pure-Go; rebuild with -tags opencl. Continuing on CPU.")
		return noop
	}
	acc, err := accel.Detect()
	if err != nil {
		logger.Warn("--gpu requested but no usable OpenCL device; continuing on CPU", "err", err)
		return noop
	}
	if err := accel.GPUSelfTest(); err != nil {
		logger.Warn("GPU self-test failed; not using the GPU tier, continuing on CPU", "err", err)
		acc.Close()
		return noop
	}
	opts.Accelerator = acc
	for _, d := range acc.Devices() {
		logger.Info("GPU tier device", "vendor", d.Vendor, "name", d.Name, "type", d.Type, "compute_units", d.ComputeUnits)
	}
	msg := fmt.Sprintf("GPU tier active across %d device(s)", len(acc.Devices()))
	if bt, ok := acc.(accel.BatchTuner); ok {
		msg += fmt.Sprintf("; autotuned batch %d", bt.OptimalBatch())
	}
	logger.Info(msg)
	return func() { acc.Close() }
}
