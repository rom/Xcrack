// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license (the Go project's
// LICENSE); see golang.org/x/crypto/argon2, from which this is derived.

// Package argon2 is a small, pure-Go Argon2 (RFC 9106) that exposes all three
// variants — Argon2d, Argon2i and Argon2id. It exists because
// golang.org/x/crypto/argon2 exports only Argon2i (Key) and Argon2id (IDKey),
// while KeePass KDBX4's default KDF is **Argon2d** (data-dependent addressing).
// The core is the x/crypto reference implementation, specialized to pure Go
// (no SSE4 asm) and run single-threaded (the engine parallelizes across
// password candidates, so an inner goroutine fan-out per hash would only
// oversubscribe). Cross-validated against the reference `argon2` CLI and, for
// the i/id variants, against x/crypto itself.
package argon2

import (
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// Version is the Argon2 version implemented here (0x13, the current one).
const Version = 0x13

// Variant selects the addressing mode.
const (
	modeD  = 0
	modeI  = 1
	modeID = 2
)

// Argon2d derives a keyLen-byte key using Argon2d (data-dependent addressing,
// KeePass KDBX4's default). time is the pass count, memory is in KiB, threads
// is the parallelism (lane count). All must be >= 1.
func Argon2d(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(modeD, password, salt, nil, nil, time, memory, threads, keyLen)
}

// Argon2i derives a key using Argon2i (data-independent addressing). Matches
// golang.org/x/crypto/argon2.Key; provided for completeness and cross-checks.
func Argon2i(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(modeI, password, salt, nil, nil, time, memory, threads, keyLen)
}

// Argon2id derives a key using Argon2id (hybrid). Matches
// golang.org/x/crypto/argon2.IDKey.
func Argon2id(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(modeID, password, salt, nil, nil, time, memory, threads, keyLen)
}

func deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if time < 1 {
		panic("argon2: number of rounds too small")
	}
	if threads < 1 {
		panic("argon2: parallelism degree too low")
	}
	h0 := initHash(password, salt, secret, data, time, memory, uint32(threads), keyLen, mode)

	memory = memory / (syncPoints * uint32(threads)) * (syncPoints * uint32(threads))
	if memory < 2*syncPoints*uint32(threads) {
		memory = 2 * syncPoints * uint32(threads)
	}
	B := initBlocks(&h0, memory, uint32(threads))
	processBlocks(B, time, memory, uint32(threads), mode)
	return extractKey(B, memory, uint32(threads), keyLen)
}

const (
	blockLength = 128
	syncPoints  = 4
)

type block [blockLength]uint64

func initHash(password, salt, key, data []byte, time, memory, threads, keyLen uint32, mode int) [blake2b.Size + 8]byte {
	var (
		h0     [blake2b.Size + 8]byte
		params [24]byte
		tmp    [4]byte
	)
	b2, _ := blake2b.New512(nil)
	binary.LittleEndian.PutUint32(params[0:4], threads)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], memory)
	binary.LittleEndian.PutUint32(params[12:16], time)
	binary.LittleEndian.PutUint32(params[16:20], uint32(Version))
	binary.LittleEndian.PutUint32(params[20:24], uint32(mode))
	b2.Write(params[:])
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(password)))
	b2.Write(tmp[:])
	b2.Write(password)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(salt)))
	b2.Write(tmp[:])
	b2.Write(salt)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(key)))
	b2.Write(tmp[:])
	b2.Write(key)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(data)))
	b2.Write(tmp[:])
	b2.Write(data)
	b2.Sum(h0[:0])
	return h0
}

func initBlocks(h0 *[blake2b.Size + 8]byte, memory, threads uint32) []block {
	var block0 [1024]byte
	B := make([]block, memory)
	for lane := uint32(0); lane < threads; lane++ {
		j := lane * (memory / threads)
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+1] {
			B[j+1][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}
	}
	return B
}

func processBlocks(B []block, time, memory, threads uint32, mode int) {
	lanes := memory / threads
	segments := lanes / syncPoints

	processSegment := func(n, slice, lane uint32) {
		var addresses, in, zero block
		if mode == modeI || (mode == modeID && n == 0 && slice < syncPoints/2) {
			in[0] = uint64(n)
			in[1] = uint64(lane)
			in[2] = uint64(slice)
			in[3] = uint64(memory)
			in[4] = uint64(time)
			in[5] = uint64(mode)
		}

		index := uint32(0)
		if n == 0 && slice == 0 {
			index = 2 // the first two blocks of each lane are already generated
			if mode == modeI || mode == modeID {
				in[6]++
				processBlock(&addresses, &in, &zero)
				processBlock(&addresses, &addresses, &zero)
			}
		}

		offset := lane*lanes + slice*segments + index
		var random uint64
		for index < segments {
			prev := offset - 1
			if index == 0 && slice == 0 {
				prev += lanes // last block in lane
			}
			if mode == modeI || (mode == modeID && n == 0 && slice < syncPoints/2) {
				if index%blockLength == 0 {
					in[6]++
					processBlock(&addresses, &in, &zero)
					processBlock(&addresses, &addresses, &zero)
				}
				random = addresses[index%blockLength]
			} else {
				random = B[prev][0]
			}
			newOffset := indexAlpha(random, lanes, segments, threads, n, slice, lane, index)
			processBlockXOR(&B[offset], &B[prev], &B[newOffset])
			index, offset = index+1, offset+1
		}
	}

	// Single-threaded: lanes within a slice are independent and all complete
	// before the next slice, so sequential processing is correct.
	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			for lane := uint32(0); lane < threads; lane++ {
				processSegment(n, slice, lane)
			}
		}
	}
}

func extractKey(B []block, memory, threads, keyLen uint32) []byte {
	lanes := memory / threads
	for lane := uint32(0); lane < threads-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[memory-1][i] ^= v
		}
	}
	var block [1024]byte
	for i, v := range B[memory-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	key := make([]byte, keyLen)
	blake2bHash(key, block[:])
	return key
}

func indexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if n == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segments, ((slice+1)%syncPoints)*segments
	if lane == refLane {
		m += index
	}
	if n == 0 {
		m, s = slice*segments, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	return phi(rand, uint64(m), uint64(s), refLane, lanes)
}

func phi(rand, m, s uint64, lane, lanes uint32) uint32 {
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * m) >> 32
	return lane*lanes + uint32((s+m-(p+1))%uint64(lanes))
}

func blake2bHash(out []byte, in []byte) {
	var b2 hash.Hash
	if n := len(out); n < blake2b.Size {
		b2, _ = blake2b.New(n, nil)
	} else {
		b2, _ = blake2b.New512(nil)
	}
	var buffer [blake2b.Size]byte
	binary.LittleEndian.PutUint32(buffer[:4], uint32(len(out)))
	b2.Write(buffer[:4])
	b2.Write(in)

	if len(out) <= blake2b.Size {
		b2.Sum(out[:0])
		return
	}
	outLen := len(out)
	b2.Sum(buffer[:0])
	b2.Reset()
	copy(out, buffer[:32])
	out = out[32:]
	for len(out) > blake2b.Size {
		b2.Write(buffer[:])
		b2.Sum(buffer[:0])
		copy(out, buffer[:32])
		out = out[32:]
		b2.Reset()
	}
	if outLen%blake2b.Size > 0 {
		r := ((outLen + 31) / 32) - 2
		b2, _ = blake2b.New(outLen-32*r, nil)
	}
	b2.Write(buffer[:])
	b2.Sum(out[:0])
}

func processBlock(out, in1, in2 *block) {
	processBlockGeneric(out, in1, in2, false)
}

func processBlockXOR(out, in1, in2 *block) {
	processBlockGeneric(out, in1, in2, true)
}
