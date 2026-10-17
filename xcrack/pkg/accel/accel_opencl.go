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
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"unsafe"

	_ "embed"

	"github.com/rom/xcrypto/prim"
)

const built = true

//go:embed kernel_pbkdf2_sha1.cl
var kernelSrcSHA1 string

//go:embed kernel_pbkdf2_sha256.cl
var kernelSrcSHA256 string

//go:embed kernel_pbkdf2_sha512.cl
var kernelSrcSHA512 string

// Host-side limits that keep each kernel single-block per PRF message. SHA-1 and
// SHA-256 use a 64-byte block (salt||INT fits when saltlen+4 <= 55); SHA-512
// uses a 128-byte block (saltlen+4 <= 111). A request outside these falls back
// to the CPU via ErrUnsupported.
const (
	maxSaltLen512 = 107
	maxSaltLen    = 51 // SHA-1 / SHA-256
	maxDKLen      = 128
)

// prf describes one PBKDF2 variant's device kernel and the host-side parameters
// that mirror it: the HMAC block size, the digest length, and the salt bound.
type prf struct {
	kernel  C.cl_kernel
	program C.cl_program
	block   int // HMAC block size (64 for SHA-1/256, 128 for SHA-512)
	digest  int // PRF output length
	saltMax int
	newHash func() hash.Hash // for HMAC key normalization (key longer than block)
}

type clAccel struct {
	devices []Device
	ctx     C.cl_context
	queue   C.cl_command_queue
	sha1    prf
	sha256  prf
	sha512  prf
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

	a := &clAccel{ctx: ctx, queue: queue}
	specs := []struct {
		src, name              string
		p                      *prf
		block, digest, saltMax int
		nh                     func() hash.Hash
	}{
		{kernelSrcSHA1, "pbkdf2_sha1", &a.sha1, 64, 20, maxSaltLen, sha1.New},
		{kernelSrcSHA256, "pbkdf2_sha256", &a.sha256, 64, 32, maxSaltLen, sha256.New},
		{kernelSrcSHA512, "pbkdf2_sha512", &a.sha512, 128, 64, maxSaltLen512, sha512.New},
	}
	for _, s := range specs {
		prog, kern, berr := buildKernel(ctx, devs, s.src, s.name)
		if berr != nil {
			a.Close()
			return nil, berr
		}
		*s.p = prf{kernel: kern, program: prog, block: s.block, digest: s.digest, saltMax: s.saltMax, newHash: s.nh}
	}
	for _, d := range devs {
		a.devices = append(a.devices, describeDevice(d))
	}
	return a, nil
}

// buildKernel compiles one embedded .cl source and returns its program+kernel.
func buildKernel(ctx C.cl_context, devs []C.cl_device_id, src, name string) (C.cl_program, C.cl_kernel, error) {
	var errc C.cl_int
	csrc := C.CString(src)
	defer C.free(unsafe.Pointer(csrc))
	srcLen := C.size_t(len(src))
	program := C.clCreateProgramWithSource(ctx, 1, &csrc, &srcLen, &errc)
	if errc != C.CL_SUCCESS {
		return nil, nil, fmt.Errorf("accel: clCreateProgramWithSource(%s): %d", name, int(errc))
	}
	if bl := C.clBuildProgram(program, C.cl_uint(len(devs)), &devs[0], nil, nil, nil); bl != C.CL_SUCCESS {
		var logSize C.size_t
		C.clGetProgramBuildInfo(program, devs[0], C.CL_PROGRAM_BUILD_LOG, 0, nil, &logSize)
		buf := make([]byte, int(logSize))
		if logSize > 0 {
			C.clGetProgramBuildInfo(program, devs[0], C.CL_PROGRAM_BUILD_LOG, logSize, unsafe.Pointer(&buf[0]), nil)
		}
		C.clReleaseProgram(program)
		return nil, nil, fmt.Errorf("accel: kernel build failed (%s): %d\n%s", name, int(bl), string(buf))
	}
	cname := C.CString(name)
	defer C.free(unsafe.Pointer(cname))
	kernel := C.clCreateKernel(program, cname, &errc)
	if errc != C.CL_SUCCESS {
		C.clReleaseProgram(program)
		return nil, nil, fmt.Errorf("accel: clCreateKernel(%s): %d", name, int(errc))
	}
	return program, kernel, nil
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
	for _, p := range []prf{a.sha1, a.sha256, a.sha512} {
		if p.kernel != nil {
			C.clReleaseKernel(p.kernel)
		}
		if p.program != nil {
			C.clReleaseProgram(p.program)
		}
	}
	if a.queue != nil {
		C.clReleaseCommandQueue(a.queue)
	}
	if a.ctx != nil {
		C.clReleaseContext(a.ctx)
	}
	return nil
}

// PBKDF2SHA1 derives keys for a batch of passwords with HMAC-SHA1.
func (a *clAccel) PBKDF2SHA1(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	return a.run(a.sha1, passwords, salt, iter, dkLen)
}

// PBKDF2SHA256 derives keys for a batch of passwords with HMAC-SHA256.
func (a *clAccel) PBKDF2SHA256(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	return a.run(a.sha256, passwords, salt, iter, dkLen)
}

// PBKDF2SHA512 derives keys for a batch of passwords with HMAC-SHA512.
func (a *clAccel) PBKDF2SHA512(passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	return a.run(a.sha512, passwords, salt, iter, dkLen)
}

// run derives keys for a batch of passwords on the device using the given PRF's
// kernel. Parameters outside the kernel's single-block assumptions return
// ErrUnsupported so the caller uses the CPU.
func (a *clAccel) run(p prf, passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	if len(passwords) == 0 {
		return nil, nil
	}
	if len(salt) > p.saltMax || dkLen <= 0 || dkLen > maxDKLen || iter <= 0 {
		return nil, ErrUnsupported
	}
	n := len(passwords)

	// Host-side HMAC key normalization: a key longer than the PRF's block is
	// replaced by its digest, exactly as HMAC specifies, so the kernel only ever
	// sees a <=block-byte, zero-padded key.
	keys := make([]byte, n*p.block)
	for i, pw := range passwords {
		k := pw
		if len(k) > p.block {
			h := p.newHash()
			h.Write(k)
			k = h.Sum(nil)
		}
		copy(keys[i*p.block:i*p.block+len(k)], k)
	}
	saltBuf := make([]byte, p.saltMax)
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

	kern := p.kernel // capture before the closure (its param shadows p)
	set := func(i C.cl_uint, size C.size_t, ptr unsafe.Pointer) {
		C.clSetKernelArg(kern, i, size, ptr)
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
	if r := C.clEnqueueNDRangeKernel(a.queue, kern, 1, nil, &global, nil, 0, nil, nil); r != C.CL_SUCCESS {
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

// GPUSelfTest derives a few known PBKDF2 vectors for each HMAC variant on the
// device and confirms they are byte-for-byte identical to the Go reference, so a
// GPU result is never trusted before the kernel is proven correct on this host.
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
		{"this-key-is-deliberately-longer-than-one-hmac-block-of-sixty-four-bytes!!", "saltysalt", 100, 32},
	}
	variants := []struct {
		name string
		h    func() hash.Hash
		fn   func([][]byte, []byte, int, int) ([][]byte, error)
	}{
		{"sha1", sha1.New, a.PBKDF2SHA1},
		{"sha256", sha256.New, a.PBKDF2SHA256},
		{"sha512", sha512.New, a.PBKDF2SHA512},
	}
	for _, v := range variants {
		for _, c := range cases {
			got, err := v.fn([][]byte{[]byte(c.pw)}, []byte(c.salt), c.iter, c.dk)
			if err != nil {
				return fmt.Errorf("GPU self-test %s (%q): %w", v.name, c.pw, err)
			}
			want, err := prim.PBKDF2(v.h, c.pw, []byte(c.salt), c.iter, c.dk)
			if err != nil {
				return err
			}
			if len(got) != 1 || !bytes.Equal(got[0], want) {
				return fmt.Errorf("GPU self-test %s MISMATCH for pw=%q iter=%d dk=%d:\n gpu %x\n cpu %x",
					v.name, c.pw, c.iter, c.dk, got[0], want)
			}
		}
	}
	return nil
}
