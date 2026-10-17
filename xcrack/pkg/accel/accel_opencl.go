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
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
	"os"
	"strings"
	"sync"
	"time"
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

//go:embed kernel_office_sha1.cl
var officeSrcSHA1 string

//go:embed kernel_office_sha256.cl
var officeSrcSHA256 string

//go:embed kernel_office_sha512.cl
var officeSrcSHA512 string

//go:embed kernel_oldoffice_md5rc4.cl
var oldofficeSrc string

// Host-side limits that keep each kernel single-block per PRF message. SHA-1 and
// SHA-256 use a 64-byte block (salt||INT fits when saltlen+4 <= 55); SHA-512
// uses a 128-byte block (saltlen+4 <= 111). A request outside these falls back
// to the CPU via ErrUnsupported.
const (
	maxSaltLen512 = 107
	maxSaltLen    = 51 // SHA-1 / SHA-256
	maxDKLen      = 128
)

// prf describes one PBKDF2 variant: the shared program, one kernel object per
// device (distinct objects so concurrent clSetKernelArg across devices is safe),
// and the host-side parameters that mirror it (HMAC block size, digest length,
// salt bound, and the hash used for HMAC key normalization).
type prf struct {
	program C.cl_program
	kernels []C.cl_kernel // one per device, parallel to clAccel.queues
	block   int
	digest  int
	saltMax int
	newHash func() hash.Hash
}

// officeKern is one Office-spin variant: a kernel object per device (parallel to
// clAccel.queues) and the digest length that seeds/outputs carry.
type officeKern struct {
	kernels []C.cl_kernel
	digest  int
}

type clAccel struct {
	devices        []Device
	ctx            C.cl_context
	queues         []C.cl_command_queue // one per backing device
	sha1           prf
	sha256         prf
	sha512         prf
	office         map[string]officeKern // Office iterated-hash spin, by algo
	officePrograms []C.cl_program        // released in Close
	oldoffice      []C.cl_kernel         // Office 97/2000 40-bit MD5+RC4 key search, one per device
	oldofficeProg  C.cl_program          // released in Close
	optimalBatch   int                   // autotuned per-dispatch batch size (BatchTuner)
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

	// Choose the best platform across all vendors. Each platform's devices are
	// described and ranked (discrete GPU > integrated GPU/APU > accelerator >
	// CPU); the platform with the highest-ranked device wins. This picks an AMD or
	// NVIDIA discrete card over an integrated APU or the CPU fallback, regardless
	// of platform order. XCRACK_GPU_DEVICE (a case-insensitive substring of the
	// device name or vendor) forces a specific device/vendor when set.
	filter := strings.ToLower(strings.TrimSpace(os.Getenv("XCRACK_GPU_DEVICE")))
	var devs []C.cl_device_id
	bestRank := -1 << 30
	for _, p := range plats {
		var ndev C.cl_uint
		if C.clGetDeviceIDs(p, C.CL_DEVICE_TYPE_ALL, 0, nil, &ndev) != C.CL_SUCCESS || ndev == 0 {
			continue
		}
		d := make([]C.cl_device_id, int(ndev))
		C.clGetDeviceIDs(p, C.CL_DEVICE_TYPE_ALL, ndev, &d[0], nil)
		rank := -1 << 30
		matched := filter == ""
		for _, dev := range d {
			desc := describeDevice(dev)
			if r := DeviceRank(desc); r > rank {
				rank = r
			}
			if filter != "" && (strings.Contains(strings.ToLower(desc.Name), filter) || strings.Contains(strings.ToLower(desc.Vendor), filter)) {
				matched = true
			}
		}
		if matched && rank > bestRank {
			bestRank, devs = rank, d
		}
	}
	if len(devs) == 0 {
		if filter != "" {
			return nil, fmt.Errorf("accel: no OpenCL device matches XCRACK_GPU_DEVICE=%q", filter)
		}
		return nil, fmt.Errorf("accel: no OpenCL devices")
	}

	var errc C.cl_int
	ctx := C.clCreateContext(nil, C.cl_uint(len(devs)), &devs[0], nil, nil, &errc)
	if errc != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clCreateContext: %d", int(errc))
	}

	a := &clAccel{ctx: ctx}
	for _, d := range devs {
		q := C.clCreateCommandQueue(ctx, d, 0, &errc)
		if errc != C.CL_SUCCESS {
			a.Close()
			return nil, fmt.Errorf("accel: clCreateCommandQueue: %d", int(errc))
		}
		a.queues = append(a.queues, q)
	}

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
		prog, kerns, berr := buildKernels(ctx, devs, s.src, s.name)
		if berr != nil {
			a.Close()
			return nil, berr
		}
		*s.p = prf{program: prog, kernels: kerns, block: s.block, digest: s.digest, saltMax: s.saltMax, newHash: s.nh}
	}
	// Office agile/standard iterated-hash spin kernels (optional capability). The
	// sha512 source exposes both the sha512 and sha384 entry points.
	a.office = map[string]officeKern{}
	officeSpecs := []struct {
		src, name, algo string
		digest          int
	}{
		{officeSrcSHA1, "office_spin_sha1", "sha1", 20},
		{officeSrcSHA256, "office_spin_sha256", "sha256", 32},
		{officeSrcSHA512, "office_spin_sha512", "sha512", 64},
		{officeSrcSHA512, "office_spin_sha384", "sha384", 48},
	}
	for _, s := range officeSpecs {
		prog, kerns, berr := buildKernels(ctx, devs, s.src, s.name)
		if berr != nil {
			a.Close()
			return nil, berr
		}
		a.officePrograms = append(a.officePrograms, prog)
		a.office[s.algo] = officeKern{kernels: kerns, digest: s.digest}
	}

	// Office 97/2000 40-bit MD5+RC4 key-search kernel (OldOfficeKeySearcher).
	ooProg, ooKerns, berr := buildKernels(ctx, devs, oldofficeSrc, "oldoffice_md5rc4")
	if berr != nil {
		a.Close()
		return nil, berr
	}
	a.oldofficeProg = ooProg
	a.oldoffice = ooKerns

	for _, d := range devs {
		a.devices = append(a.devices, describeDevice(d))
	}
	a.optimalBatch = a.autotuneBatch()
	return a, nil
}

// buildKernels compiles one embedded .cl source and returns its program plus one
// kernel object per device (distinct objects so each device's queue can set
// args and enqueue concurrently without clobbering another's).
func buildKernels(ctx C.cl_context, devs []C.cl_device_id, src, name string) (C.cl_program, []C.cl_kernel, error) {
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
	kerns := make([]C.cl_kernel, len(devs))
	for i := range devs {
		k := C.clCreateKernel(program, cname, &errc)
		if errc != C.CL_SUCCESS {
			for j := 0; j < i; j++ {
				C.clReleaseKernel(kerns[j])
			}
			C.clReleaseProgram(program)
			return nil, nil, fmt.Errorf("accel: clCreateKernel(%s): %d", name, int(errc))
		}
		kerns[i] = k
	}
	return program, kerns, nil
}

func describeDevice(d C.cl_device_id) Device {
	name := devStr(d, C.CL_DEVICE_NAME)
	vendor := devStr(d, C.CL_DEVICE_VENDOR)
	var dt C.cl_device_type
	C.clGetDeviceInfo(d, C.CL_DEVICE_TYPE, C.size_t(unsafe.Sizeof(dt)), unsafe.Pointer(&dt), nil)
	var cu C.cl_uint
	C.clGetDeviceInfo(d, C.CL_DEVICE_MAX_COMPUTE_UNITS, C.size_t(unsafe.Sizeof(cu)), unsafe.Pointer(&cu), nil)
	var unified C.cl_bool
	C.clGetDeviceInfo(d, C.CL_DEVICE_HOST_UNIFIED_MEMORY, C.size_t(unsafe.Sizeof(unified)), unsafe.Pointer(&unified), nil)
	typ := "OTHER"
	switch {
	case dt&C.CL_DEVICE_TYPE_GPU != 0:
		typ = "GPU"
	case dt&C.CL_DEVICE_TYPE_CPU != 0:
		typ = "CPU"
	case dt&C.CL_DEVICE_TYPE_ACCELERATOR != 0:
		typ = "ACCELERATOR"
	}
	return Device{Name: name, Vendor: vendor, Type: typ, ComputeUnits: int(cu), UnifiedMem: unified == C.CL_TRUE}
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
		for _, k := range p.kernels {
			if k != nil {
				C.clReleaseKernel(k)
			}
		}
		if p.program != nil {
			C.clReleaseProgram(p.program)
		}
	}
	for _, ok := range a.office {
		for _, k := range ok.kernels {
			if k != nil {
				C.clReleaseKernel(k)
			}
		}
	}
	for _, p := range a.officePrograms {
		if p != nil {
			C.clReleaseProgram(p)
		}
	}
	for _, k := range a.oldoffice {
		if k != nil {
			C.clReleaseKernel(k)
		}
	}
	if a.oldofficeProg != nil {
		C.clReleaseProgram(a.oldofficeProg)
	}
	for _, q := range a.queues {
		if q != nil {
			C.clReleaseCommandQueue(q)
		}
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

// run derives keys for a batch of passwords using the given PRF. With more than
// one backing device it splits the batch into contiguous chunks, one per device,
// and runs them concurrently (each device has its own queue and kernel object);
// results are reassembled in input order. Parameters outside the kernel's
// single-block assumptions return ErrUnsupported so the caller uses the CPU.
func (a *clAccel) run(p prf, passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	if len(passwords) == 0 {
		return nil, nil
	}
	if len(salt) > p.saltMax || dkLen <= 0 || dkLen > maxDKLen || iter <= 0 {
		return nil, ErrUnsupported
	}
	n := len(passwords)
	nd := len(a.queues)
	if nd <= 1 {
		return a.runOne(p, 0, passwords, salt, iter, dkLen)
	}

	res := make([][]byte, n)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	chunk := (n + nd - 1) / nd
	for d := 0; d < nd; d++ {
		lo := d * chunk
		if lo >= n {
			break
		}
		hi := lo + chunk
		if hi > n {
			hi = n
		}
		wg.Add(1)
		go func(dev, lo, hi int) {
			defer wg.Done()
			part, err := a.runOne(p, dev, passwords[lo:hi], salt, iter, dkLen)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			copy(res[lo:hi], part)
		}(d, lo, hi)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return res, nil
}

// runOne derives a sub-batch on a single device (its own queue + kernel object).
func (a *clAccel) runOne(p prf, dev int, passwords [][]byte, salt []byte, iter, dkLen int) ([][]byte, error) {
	n := len(passwords)
	if n == 0 {
		return nil, nil
	}
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

	kern := p.kernels[dev]
	queue := a.queues[dev]
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
	if r := C.clEnqueueNDRangeKernel(queue, kern, 1, nil, &global, nil, 0, nil, nil); r != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clEnqueueNDRangeKernel: %d", int(r))
	}
	if r := C.clEnqueueReadBuffer(queue, outBuf, C.CL_TRUE, 0, C.size_t(len(out)), unsafe.Pointer(&out[0]), 0, nil, nil); r != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clEnqueueReadBuffer: %d", int(r))
	}

	res := make([][]byte, n)
	for i := 0; i < n; i++ {
		res[i] = append([]byte(nil), out[i*dkLen:(i+1)*dkLen]...)
	}
	return res, nil
}

// OfficeSpin runs the Office agile/standard iterated-hash spin for a batch of
// digest-length seeds (cur0 = H(salt||UTF16LE(pw))), returning the final digest
// per seed. algo is "sha1"|"sha256"|"sha384"|"sha512". An unknown algo, a
// non-positive spin, or a seed of the wrong length returns ErrUnsupported so the
// caller falls back to the CPU. It implements the OfficeHasher capability, and
// splits a batch across devices like run.
func (a *clAccel) OfficeSpin(seeds [][]byte, spin int, algo string) ([][]byte, error) {
	ok, found := a.office[algo]
	if !found || spin <= 0 {
		return nil, ErrUnsupported
	}
	n := len(seeds)
	if n == 0 {
		return nil, nil
	}
	for _, s := range seeds {
		if len(s) != ok.digest {
			return nil, ErrUnsupported
		}
	}
	nd := len(a.queues)
	if nd <= 1 {
		return a.runOneOffice(ok, 0, seeds, spin)
	}
	res := make([][]byte, n)
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	chunk := (n + nd - 1) / nd
	for d := 0; d < nd; d++ {
		lo := d * chunk
		if lo >= n {
			break
		}
		hi := lo + chunk
		if hi > n {
			hi = n
		}
		wg.Add(1)
		go func(dev, lo, hi int) {
			defer wg.Done()
			part, err := a.runOneOffice(ok, dev, seeds[lo:hi], spin)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			copy(res[lo:hi], part)
		}(d, lo, hi)
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return res, nil
}

// runOneOffice spins a sub-batch on one device (its own queue + kernel object).
func (a *clAccel) runOneOffice(ok officeKern, dev int, seeds [][]byte, spin int) ([][]byte, error) {
	n := len(seeds)
	if n == 0 {
		return nil, nil
	}
	dlen := ok.digest
	in := make([]byte, n*dlen)
	for i, s := range seeds {
		copy(in[i*dlen:], s)
	}
	out := make([]byte, n*dlen)

	var errc C.cl_int
	seedsBuf := C.clCreateBuffer(a.ctx, C.cl_mem_flags(C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR), C.size_t(len(in)), unsafe.Pointer(&in[0]), &errc)
	if errc != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clCreateBuffer(office seeds): %d", int(errc))
	}
	defer C.clReleaseMemObject(seedsBuf)
	outBuf := C.clCreateBuffer(a.ctx, C.CL_MEM_WRITE_ONLY, C.size_t(len(out)), nil, &errc)
	if errc != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clCreateBuffer(office out): %d", int(errc))
	}
	defer C.clReleaseMemObject(outBuf)

	kern := ok.kernels[dev]
	queue := a.queues[dev]
	cSpin := C.cl_uint(spin)
	C.clSetKernelArg(kern, 0, C.size_t(unsafe.Sizeof(seedsBuf)), unsafe.Pointer(&seedsBuf))
	C.clSetKernelArg(kern, 1, C.size_t(unsafe.Sizeof(cSpin)), unsafe.Pointer(&cSpin))
	C.clSetKernelArg(kern, 2, C.size_t(unsafe.Sizeof(outBuf)), unsafe.Pointer(&outBuf))

	global := C.size_t(n)
	if r := C.clEnqueueNDRangeKernel(queue, kern, 1, nil, &global, nil, 0, nil, nil); r != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clEnqueueNDRangeKernel(office): %d", int(r))
	}
	if r := C.clEnqueueReadBuffer(queue, outBuf, C.CL_TRUE, 0, C.size_t(len(out)), unsafe.Pointer(&out[0]), 0, nil, nil); r != C.CL_SUCCESS {
		return nil, fmt.Errorf("accel: clEnqueueReadBuffer(office): %d", int(r))
	}
	res := make([][]byte, n)
	for i := 0; i < n; i++ {
		res[i] = append([]byte(nil), out[i*dlen:(i+1)*dlen]...)
	}
	return res, nil
}

// OptimalBatch reports the autotuned per-dispatch batch size (BatchTuner). It is
// measured once at Detect; see autotuneBatch.
// oldofficeChunk is the number of trunc indices swept per kernel enqueue. The
// full 2^40 space is swept in chunks so a very large shard still progresses and
// a hit returns promptly; each work-item does three MD5s and one RC4.
const oldofficeChunk = 1 << 22

// OldOfficeKeySearch sweeps the Office 97/2000 40-bit trunc keyspace
// [start, start+count) on device 0, implementing OldOfficeKeySearcher. It is
// byte-for-byte equivalent to officebinary.RC4KeyAttack; the caller re-checks a
// hit on the CPU. Unsupported salt sizes return ErrUnsupported so the caller
// falls back to the CPU sweep.
func (a *clAccel) OldOfficeKeySearch(salt, encVerifier, encVerifierHash []byte, start, count uint64) ([]byte, bool, error) {
	if len(encVerifier) != 16 || len(encVerifierHash) != 16 || len(salt) == 0 || len(salt) > 16 {
		return nil, false, ErrUnsupported
	}
	if count == 0 {
		return nil, false, nil
	}
	dev := 0
	kern := a.oldoffice[dev]
	queue := a.queues[dev]

	var errc C.cl_int
	saltBuf := C.clCreateBuffer(a.ctx, C.cl_mem_flags(C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR), C.size_t(len(salt)), unsafe.Pointer(&salt[0]), &errc)
	if errc != C.CL_SUCCESS {
		return nil, false, fmt.Errorf("accel: clCreateBuffer(oldoffice salt): %d", int(errc))
	}
	defer C.clReleaseMemObject(saltBuf)
	ev := make([]byte, 32)
	copy(ev, encVerifier)
	copy(ev[16:], encVerifierHash)
	evBuf := C.clCreateBuffer(a.ctx, C.cl_mem_flags(C.CL_MEM_READ_ONLY|C.CL_MEM_COPY_HOST_PTR), C.size_t(32), unsafe.Pointer(&ev[0]), &errc)
	if errc != C.CL_SUCCESS {
		return nil, false, fmt.Errorf("accel: clCreateBuffer(oldoffice ev): %d", int(errc))
	}
	defer C.clReleaseMemObject(evBuf)
	out := make([]uint32, 4) // [0]=found, [1]=idx low32, [2]=idx high
	outBuf := C.clCreateBuffer(a.ctx, C.cl_mem_flags(C.CL_MEM_READ_WRITE|C.CL_MEM_COPY_HOST_PTR), C.size_t(16), unsafe.Pointer(&out[0]), &errc)
	if errc != C.CL_SUCCESS {
		return nil, false, fmt.Errorf("accel: clCreateBuffer(oldoffice out): %d", int(errc))
	}
	defer C.clReleaseMemObject(outBuf)

	cSaltLen := C.cl_uint(len(salt))
	end := start + count
	if end < start { // overflow guard; callers bound to 2^40
		end = ^uint64(0)
	}
	for base := start; base < end; base += oldofficeChunk {
		n := uint64(oldofficeChunk)
		if base+n > end {
			n = end - base
		}
		cStart := C.cl_ulong(base)
		cN := C.cl_uint(n)
		C.clSetKernelArg(kern, 0, C.size_t(unsafe.Sizeof(saltBuf)), unsafe.Pointer(&saltBuf))
		C.clSetKernelArg(kern, 1, C.size_t(unsafe.Sizeof(cSaltLen)), unsafe.Pointer(&cSaltLen))
		C.clSetKernelArg(kern, 2, C.size_t(unsafe.Sizeof(evBuf)), unsafe.Pointer(&evBuf))
		C.clSetKernelArg(kern, 3, C.size_t(unsafe.Sizeof(cStart)), unsafe.Pointer(&cStart))
		C.clSetKernelArg(kern, 4, C.size_t(unsafe.Sizeof(cN)), unsafe.Pointer(&cN))
		C.clSetKernelArg(kern, 5, C.size_t(unsafe.Sizeof(outBuf)), unsafe.Pointer(&outBuf))
		global := C.size_t(n)
		if r := C.clEnqueueNDRangeKernel(queue, kern, 1, nil, &global, nil, 0, nil, nil); r != C.CL_SUCCESS {
			return nil, false, fmt.Errorf("accel: clEnqueueNDRangeKernel(oldoffice): %d", int(r))
		}
		if r := C.clEnqueueReadBuffer(queue, outBuf, C.CL_TRUE, 0, C.size_t(16), unsafe.Pointer(&out[0]), 0, nil, nil); r != C.CL_SUCCESS {
			return nil, false, fmt.Errorf("accel: clEnqueueReadBuffer(oldoffice): %d", int(r))
		}
		if out[0] != 0 {
			idx := uint64(out[1]) | uint64(out[2])<<32
			return []byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), byte(idx >> 32)}, true, nil
		}
	}
	return nil, false, nil
}

func (a *clAccel) OptimalBatch() int { return a.optimalBatch }

// autotuneBatch measures SHA-1 derivation throughput at a few batch sizes and
// picks the smallest size whose throughput is within ~10% of the best observed,
// so the engine amortizes device round-trips without oversized batches. It is a
// quick micro-benchmark (low iteration count) run once at startup; on failure it
// falls back to a safe default. The chosen size scales with device count so a
// multi-GPU context gets enough work to split.
func (a *clAccel) autotuneBatch() int {
	const defaultBatch = 2048
	sizes := []int{256, 512, 1024, 2048, 4096, 8192}
	salt := []byte("autotune-salt-16")
	const iter, dk = 256, 32
	bestRate := 0.0
	bestIdx := -1
	rates := make([]float64, len(sizes))
	for i, sz := range sizes {
		pws := make([][]byte, sz)
		for j := range pws {
			pws[j] = []byte{byte(j), byte(j >> 8), 'x'}
		}
		start := time.Now()
		if _, err := a.runOne(a.sha1, 0, pws, salt, iter, dk); err != nil {
			if bestIdx < 0 {
				return defaultBatch
			}
			break
		}
		el := time.Since(start).Seconds()
		if el <= 0 {
			el = 1e-9
		}
		rates[i] = float64(sz) / el
		if rates[i] > bestRate {
			bestRate, bestIdx = rates[i], i
		}
	}
	if bestIdx < 0 {
		return defaultBatch
	}
	chosen := sizes[bestIdx]
	for i := 0; i <= bestIdx; i++ {
		if rates[i] >= 0.9*bestRate {
			chosen = sizes[i]
			break
		}
	}
	if nd := len(a.queues); nd > 1 {
		chosen *= nd // give every device a full chunk after the split
	}
	return chosen
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

	// Office agile/standard iterated-hash spin: the device output must equal
	// prim.OfficeAgileHash for every variant and a few spin counts. The CPU does
	// the first hash (cur0 = H(salt||UTF16LE(pw))); the device does the spin.
	oh, ok := a.(OfficeHasher)
	if !ok {
		return fmt.Errorf("GPU self-test: accelerator does not implement OfficeHasher")
	}
	officeVariants := []struct {
		algo string
		nh   func() hash.Hash
	}{
		{"sha1", sha1.New}, {"sha256", sha256.New}, {"sha384", sha512.New384}, {"sha512", sha512.New},
	}
	osalt := []byte("office-salt-16by")
	opw := prim.UTF16LE([]byte("Pa55w0rd! spin"))
	for _, v := range officeVariants {
		for _, spin := range []int{1, 2, 50, 1000} {
			h := v.nh()
			h.Write(osalt)
			h.Write(opw)
			seed := h.Sum(nil)
			got, err := oh.OfficeSpin([][]byte{seed}, spin, v.algo)
			if err != nil {
				return fmt.Errorf("GPU self-test office %s (spin %d): %w", v.algo, spin, err)
			}
			want := prim.OfficeAgileHash(v.nh, osalt, opw, spin)
			if len(got) != 1 || !bytes.Equal(got[0], want) {
				return fmt.Errorf("GPU self-test office %s MISMATCH (spin %d):\n gpu %x\n cpu %x",
					v.algo, spin, got[0], want)
			}
		}
	}

	// Office 97/2000 40-bit MD5+RC4 key search (OldOfficeKeySearcher): build a
	// valid verifier for a known trunc with the documented algorithm, then sweep a
	// small range containing it and confirm the device recovers exactly that trunc.
	if ks, ok := a.(OldOfficeKeySearcher); ok {
		salt := []byte("0123456789abcdef") // 16-byte EncryptionHeader salt
		for _, idx := range []uint64{0, 1, 0x00000000ff, 0x0102030405} {
			trunc := []byte{byte(idx), byte(idx >> 8), byte(idx >> 16), byte(idx >> 24), byte(idx >> 32)}
			encV, encVH := oldOfficeVerifier(trunc, salt)
			// A window of ~4096 indices around idx (clamped to >= 0), big enough to
			// exercise many non-matching work-items alongside the single hit.
			start := uint64(0)
			if idx > 2048 {
				start = idx - 2048
			}
			got, found, err := ks.OldOfficeKeySearch(salt, encV, encVH, start, 4096)
			if err != nil {
				return fmt.Errorf("GPU self-test oldoffice (idx %#x): %w", idx, err)
			}
			if !found || !bytes.Equal(got, trunc) {
				return fmt.Errorf("GPU self-test oldoffice MISMATCH (idx %#x): found=%v got %x want %x",
					idx, found, got, trunc)
			}
		}
	} else {
		return fmt.Errorf("GPU self-test: accelerator does not implement OldOfficeKeySearcher")
	}
	return nil
}

// oldOfficeVerifier builds a valid (encVerifier, encVerifierHash) pair for a
// given 40-bit trunc and salt, following MS-OFFCRYPTO 2.3.6 — the inverse of the
// key-attack check, used only to construct self-test / known-answer inputs.
func oldOfficeVerifier(trunc, salt []byte) (encVerifier, encVerifierHash []byte) {
	inter := make([]byte, 0, 16*(len(trunc)+len(salt)))
	for i := 0; i < 16; i++ {
		inter = append(inter, trunc...)
		inter = append(inter, salt...)
	}
	t2 := md5.Sum(inter) //nolint:gosec // MS-OFFCRYPTO mandates MD5
	kb := make([]byte, 9)
	copy(kb, t2[:5])                    // kb[5:9] == LE32(block 0)
	key := md5.Sum(kb)                  //nolint:gosec
	plain := []byte("verifier-block!!") // 16 bytes
	ph := md5.Sum(plain)                //nolint:gosec
	buf := append(append([]byte{}, plain...), ph[:]...)
	c, _ := rc4.NewCipher(key[:16]) //nolint:gosec // RC4 is the scheme's cipher
	out := make([]byte, 32)
	c.XORKeyStream(out, buf)
	return out[:16], out[16:]
}
