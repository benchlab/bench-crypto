// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package blake2s

import (
	"encoding/binary"
	"errors"
	"io"
)

// XOF defines the interface to hash functions that
// support arbitrary-length output.
type XOF interface {
	// Write absorbs more data into the hash's state. It panics if called
	// after Read.
	io.Writer

	// Read reads more output from the hash. It returns io.EOF if the limit
	// has been reached.
	io.Reader

	// Clone returns a copy of the XOF in its current state.
	Clone() XOF

	// Reset resets the XOF to its initial state.
	Reset()
}

// OutputLengthUnknown can be used as the size argument to NewXOF to indicate
// the the length of the output is not known in advance.
const OutputLengthUnknown = 0

// magicUnknownOutputLength is a magic value for the output size that indicates
// an unknown number of output bytes.
const magicUnknownOutputLength = 65535

// maxOutputLength is the absolute maximum number of bytes to produce when the
// number of output bytes is unknown.
const maxOutputLength = (1 << 32) * 32

// NewXOF creates a new variable-output-length hash. The hash either produce a
// known number of bytes (1 <= size < 65535), or an unknown number of bytes
// (size == OutputLengthUnknown). In the latter case, an absolute limit of
// 128GiB applies.
//
// A non-nil key turns the hash into a MAC. The key must between
// zero and 32 bytes long.
func NewXOF(size uint16, key []byte) (XOF, error) {
	if len(key) > Size {
		return nil, errKeySize
	}
	if size == magicUnknownOutputLength {
		// 2^16-1 indicates an unknown number of bytes and thus isn't a
		// valid length.
		return nil, errors.New("blake2s: XOF length too large")
	}
	if size == OutputLengthUnknown {
		size = magicUnknownOutputLength
	}
	x := &xof{
		d: digest{
			size:   Size,
			keyLen: len(key),
		},
		length: size,
	}
	copy(x.d.key[:], key)
	x.Reset()
	return x, nil
}

type xof struct {
	d                digest
	length           uint16
	remaining        uint64
	cfg, root, chunk [Size]byte
	offset           int
	nodeOffset       uint32
	readMode         bool
}

func (x *xof) Write(p []byte) (n int, err error) {
	if x.readMode {
		panic("blake2s: write to XOF after read")
	}
	return x.d.Write(p)
}

func (x *xof) Clone() XOF {
	clone := *x
	return &clone
}

func (x *xof) Reset() {
	x.cfg[0] = byte(Size)
	binary.LittleEndian.PutUint32(x.cfg[4:], uint32(Size)) // leaf length
	binary.LittleEndian.PutUint16(x.cfg[12:], x.length)    // XOF length
	x.cfg[15] = byte(Size)                                 // inner hash size

	x.d.Reset()
	x.d.h[3] ^= uint32(x.length)

	x.remaining = uint64(x.length)
	if x.remaining == magicUnknownOutputLength {
		x.remaining = maxOutputLength
	}
	x.offset, x.nodeOffset = 0, 0
	x.readMode = false
}

func (x *xof) Read(p []byte) (n int, err error) {
	if !x.readMode {
		x.d.finalize(&x.root)
		x.readMode = true
	}

	if x.remaining == 0 {
		return 0, io.EOF
	}

	n = len(p)
	if uint64(n) > x.remaining {
		n = int(x.remaining)
		p = p[:n]
	}

	if x.offset > 0 {
		chunkRemaining := Size - x.offset
		if n < chunkRemaining {
			x.offset += copy(p, x.chunk[x.offset:])
			x.remaining -= uint64(n)
			return
		}
		copy(p, x.chunk[x.offset:])
		p = p[chunkRemaining:]
		x.offset = 0
		x.remaining -= uint64(chunkRemaining)
	}

	for len(p) >= Size {
		binary.LittleEndian.PutUint32(x.cfg[8:], x.nodeOffset)
		x.nodeOffset++

		x.d.initConfig(&x.cfg)
		x.d.Write(x.root[:])
		x.d.finalize(&x.chunk)

		copy(p, x.chunk[:])
		p = p[Size:]
		x.remaining -= uint64(Size)
	}

	if todo := len(p); todo > 0 {
		if x.remaining < uint64(Size) {
			x.cfg[0] = byte(x.remaining)
		}
		binary.LittleEndian.PutUint32(x.cfg[8:], x.nodeOffset)
		x.nodeOffset++

		x.d.initConfig(&x.cfg)
		x.d.Write(x.root[:])
		x.d.finalize(&x.chunk)

		x.offset = copy(p, x.chunk[:todo])
		x.remaining -= uint64(todo)
	}

	return
}

func (d *digest) initConfig(cfg *[Size]byte) {
	d.offset, d.c[0], d.c[1] = 0, 0, 0
	for i := range d.h {
		d.h[i] = iv[i] ^ binary.LittleEndian.Uint32(cfg[i*4:])
	}
}