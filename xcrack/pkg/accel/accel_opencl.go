//go:build opencl

// This file is the OpenCL backend, compiled only with `-tags opencl` and only
// linked into xcrackd on a host with an OpenCL SDK + runtime. It is the single
// cgo exception sanctioned by ADR 0001 and never built by CI or the default
// `go build`. Everything here is isolated behind the build tag so a default
// pure-Go build never sees cgo or libOpenCL.

package accel

/*
#cgo LDFLAGS: -lOpenCL
#define CL_TARGET_OPENCL_VERSION 120
#include <CL/cl.h>
#include <stdlib.h>
*/
import "C"

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"unsafe"

	_ "embed"

	"github.com/rom/xcrypto/prim"
)

const built = true

//go:embed kernel_pbkdf2_sha1.cl
var kernelSrc string

// Host-side limits that keep the kernel single-block per PRF message. A request
// outside these falls back to the CPU via ErrUnsupported.
const (
	maxSaltLen = 51
	maxDKLen   = 80
)

type clAccel struct {
	devices []Device
	ctx     C.cl_context
	queue   C.cl_command_queue
	program C.cl_program
	kernel  C.cl_kernel
}

// Detect enumerates OpenCL devices, builds the PBKDF2 kernel, and returns a
// ready accelerator over the first platform that exposes a device (preferring
// a GPU). It returns an error (caller falls back to CPU) if no device or the
// build fails.
func Detect() (Accelerator, error) {
	var nplat C.cl_uint
	if C.clGetPlatformIDs(0, nil, &nplat) != C.CL_SUCCESS || nplat == 0 {
		return nil, fmt.Errorf("accel: no OpenCL platforms")
	}
	plats := make([]C.cl_platform_id, int(nplat))
	C.clGetPlatformIDs(nplat, &plats[0], nil)

	var chosenPlat C.cl_platform_id
	var devs []C.cl_device_id
	for _, p := range plats {
		var ndev C.cl_uint
		if C.clGetDeviceIDs(p, C.CL_DEVICE_TYPE_ALL, 0, nil, &ndev) != C.CL_SUCCESS || ndev == 0 {
			continue
		}
		d := make([]C.cl_device_id, int(ndev))
		C.clGetDeviceIDs(p, C.CL_DEVICE_TYPE_ALL, ndev, &d[0], nil)
		chosenPlat, devs = p, d
		// Prefer a platform exposing a GPU.
		var g C.cl_uint
		if C.clGetDeviceIDs(p, C.CL_DEVICE_TYPE_GPU, 0, nil, &g) == C.CL_SUCCESS && g > 0 {
			break
		}
	}
	if len(devs) == 0 {
		return nil, fmt.Errorf("accel: no OpenCL devices")
	}
	_ = chosenPlat

	var errc C.cl_int
	ctx := C.clCreateContext(nil, C.cl_uint(len(devs)), &devs[0], nil, nil, &errc)
	if errc != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clCreateContext: %d", int(errc))
	}
	queue := C.clCreateCommandQueue(ctx, devs[0], 0, &errc)
	if errc != C.CL_SUCCESS {
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf("accel: clCreateCommandQueue: %d", int(errc))
	}

	csrc := C.CString(kernelSrc)
	defer C.free(unsafe.Pointer(csrc))
	srcLen := C.size_t(len(kernelSrc))
	program := C.clCreateProgramWithSource(ctx, 1, &csrc, &srcLen, &errc)
	if errc != C.CL_SUCCESS {
		C.clReleaseCommandQueue(queue)
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf("accel: clCreateProgramWithSource: %d", int(errc))
	}
	if bl := C.clBuildProgram(program, C.cl_uint(len(devs)), &devs[0], nil, nil, nil); bl != C.CL_SUCCESS {
		var logSize C.size_t
		C.clGetProgramBuildInfo(program, devs[0], C.CL_PROGRAM_BUILD_LOG, 0, nil, &logSize)
		buf := make([]byte, int(logSize))
		if logSize > 0 {
			C.clGetProgramBuildInfo(program, devs[0], C.CL_PROGRAM_BUILD_LOG, logSize, unsafe.Pointer(&buf[0]), nil)
		}
		C.clReleaseProgram(program)
		C.clReleaseCommandQueue(queue)
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf("accel: kernel build failed: %d\n%s", int(bl), string(buf))
	}
	kname := C.CString("pbkdf2_sha1")
	defer C.free(unsafe.Pointer(kname))
	kernel := C.clCreateKernel(program, kname, &errc)
	if errc != C.CL_SUCCESS {
		C.clReleaseProgram(program)
		C.clReleaseCommandQueue(queue)
		C.clReleaseContext(ctx)
		return nil, fmt.Errorf("accel: clCreateKernel: %d", int(errc))
	}

	a := &clAccel{ctx: ctx, queue: queue, program: program, kernel: kernel}
	for _, d := range devs {
		a.devices = append(a.devices, describeDevice(d))
	}
	return a, nil
}

func describeDevice(d C.cl_device_id) Device {
	name := devStr(d, C.CL_DEVICE_NAME)
	vendor := devStr(d, C.CL_DEVICE_VENDOR)
	var dt C.cl_device_type
	C.clGetDeviceInfo(d, C.CL_DEVICE_TYPE, C.size_t(unsafe.Sizeof(dt)), unsafe.Pointer(&dt), nil)
	var cu C.cl_uint
	C.clGetDeviceInfo(d, C.CL_DEVICE_MAX_COMPUTE_UNITS, C.size_t(unsafe.Sizeof(cu)), unsafe.Pointer(&cu), nil)
	typ := "OTHER"
	switch {
	case dt&C.CL_DEVICE_TYPE_GPU != 0:
		typ = "GPU"
	case dt&C.CL_DEVICE_TYPE_CPU != 0:
		typ = "CPU"
	case dt&C.CL_DEVICE_TYPE_ACCELERATOR != 0:
		typ = "ACCELERATOR"
	}
	return Device{Name: name, Vendor: vendor, Type: typ, ComputeUnits: int(cu)}
}

func devStr(d C.cl_device_id, param C.cl_device_info) string {
	var n C.size_t
	C.clGetDeviceInfo(d, param, 0, nil, &n)
	if n == 0 {
		return ""
	}
	buf := make([]byte, int(n))
	C.clGetDeviceInfo(d, param, n, unsafe.Pointer(&buf[0]), nil)
	if n > 0 && buf[n-1] == 0 {
		buf = buf[:n-1]
	}
	return string(buf)
}

func (a *clAccel) Devices() []Device { return a.devices }

func (a *clAccel) Close() error {
	C.clReleaseKernel(a.kernel)
	C.clReleaseProgram(a.program)
	C.clReleaseCommandQueue(a.queue)
	C.clReleaseContext(a.ctx)
	return nil
}

// PBKDF2SHA1 derives keys for a batch of passwords on the device. Parameters
// outside the kernel's single-block assumptions return ErrUnsupported so the
// caller uses the CPU.
func (a *clAccel) PBKDF2SHA1(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	if len(passwords) == 0 {
		return nil, nil
	}
	if len(salt) > maxSaltLen || dkLen <= 0 || dkLen > maxDKLen || iter <= 0 {
		return nil, ErrUnsupported
	}
	n := len(passwords)

	// Host-side HMAC key normalization: a key longer than the SHA-1 block is
	// replaced by its digest, exactly as HMAC specifies, so the kernel only ever
	// sees a <=64-byte, zero-padded key.
	keys := make([]byte, n*64)
	for i, pw := range passwords {
		k := pw
		if len(k) > 64 {
			s := sha1.Sum(k)
			k = s[:]
		}
		copy(keys[i*64:(i+1)*64], k)
	}
	saltBuf := make([]byte, maxSaltLen)
	copy(saltBuf, salt)
	out := make([]byte, n*dkLen)

	var errc C.cl_int
	mkBuf := func(flags C.cl_mem_flags, data []byte) (C.cl_mem, error) {
		var ptr unsafe.Pointer
		if len(data) > 0 {
			ptr = unsafe.Pointer(&data[0])
		}
		m := C.clCreateBuffer(a.ctx, flags, C.size_t(len(data)), ptr, &errc)
		if errc != C.CL_SUCCESS {
			return nil, fmt.Errorf("accel: clCreateBuffer: %d", int(errc))
		}
		return m, nil
	}
	ro := C.cl_mem_flags(C.CL_MEM_READ_ONLY | C.CL_MEM_COPY_HOST_PTR)
	keysBuf, err := mkBuf(ro, keys)
	if err != nil {
		return nil, err
	}
	defer C.clReleaseMemObject(keysBuf)
	saltB, err := mkBuf(ro, saltBuf)
	if err != nil {
		return nil, err
	}
	defer C.clReleaseMemObject(saltB)
	outBuf := C.clCreateBuffer(a.ctx, C.CL_MEM_WRITE_ONLY, C.size_t(len(out)), nil, &errc)
	if errc != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clCreateBuffer(out): %d", int(errc))
	}
	defer C.clReleaseMemObject(outBuf)
	// keylens arg is vestigial (padding handled host-side) but kept in the
	// signature; pass a 1-word dummy buffer.
	dummy := make([]byte, 4)
	klBuf, err := mkBuf(ro, dummy)
	if err != nil {
		return nil, err
	}
	defer C.clReleaseMemObject(klBuf)

	set := func(i C.cl_uint, size C.size_t, p unsafe.Pointer) {
		C.clSetKernelArg(a.kernel, i, size, p)
	}
	set(0, C.size_t(unsafe.Sizeof(keysBuf)), unsafe.Pointer(&keysBuf))
	set(1, C.size_t(unsafe.Sizeof(klBuf)), unsafe.Pointer(&klBuf))
	set(2, C.size_t(unsafe.Sizeof(saltB)), unsafe.Pointer(&saltB))
	cSalt := C.cl_uint(len(salt))
	cIter := C.cl_uint(iter)
	cDK := C.cl_uint(dkLen)
	set(3, C.size_t(unsafe.Sizeof(cSalt)), unsafe.Pointer(&cSalt))
	set(4, C.size_t(unsafe.Sizeof(cIter)), unsafe.Pointer(&cIter))
	set(5, C.size_t(unsafe.Sizeof(cDK)), unsafe.Pointer(&cDK))
	set(6, C.size_t(unsafe.Sizeof(outBuf)), unsafe.Pointer(&outBuf))

	global := C.size_t(n)
	if r := C.clEnqueueNDRangeKernel(a.queue, a.kernel, 1, nil, &global, nil, 0, nil, nil); r != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clEnqueueNDRangeKernel: %d", int(r))
	}
	if r := C.clEnqueueReadBuffer(a.queue, outBuf, C.CL_TRUE, 0, C.size_t(len(out)), unsafe.Pointer(&out[0]), 0, nil, nil); r != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clEnqueueReadBuffer: %d", int(r))
	}

	res := make([][]byte, n)
	for i := 0; i < n; i++ {
		res[i] = append([]byte(nil), out[i*dkLen:(i+1)*dkLen]...)
	}
	return res, nil
}

// GPUSelfTest derives a few known PBKDF2-HMAC-SHA1 vectors on the device and
// confirms they are byte-for-byte identical to the Go reference, so a GPU
// result is never trusted before the kernel is proven correct on this host.
func GPUSelfTest() error {
	a, err := Detect()
	if err != nil {
		return err
	}
	defer a.Close()
	cases := []struct {
		pw, salt string
		iter, dk int
	}{
		{"hashcat", "saltsalt", 1000, 32},
		{"", "abc", 1, 20},
		{"password", "NaCl1234salt", 2048, 40},
		{"a-longer-passphrase-here", "0123456789abcdef0123", 500, 66},
	}
	for _, c := range cases {
		got, err := a.PBKDF2SHA1([][]byte{[]byte(c.pw)}, []byte(c.salt), c.iter, c.dk)
		if err != nil {
			return fmt.Errorf("GPU self-test (%q): %w", c.pw, err)
		}
		want, err := prim.PBKDF2(sha1.New, c.pw, []byte(c.salt), c.iter, c.dk)
		if err != nil {
			return err
		}
		if len(got) != 1 || !bytes.Equal(got[0], want) {
			return fmt.Errorf("GPU self-test MISMATCH for pw=%q iter=%d dk=%d:\n gpu %x\n cpu %x",
				c.pw, c.iter, c.dk, got[0], want)
		}
	}
	return nil
}
