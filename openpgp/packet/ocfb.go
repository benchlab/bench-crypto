// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// OpenPGP CFB Mode. http://tools.ietf.org/html/rfc4880#section-13.9

package packet

import (
	"github.com/benchlab/bench-crypto/cipher"
)

type ocfbEncrypter struct {
	b       cipher.Chunk
	fre     []byte
	outUsed int
}

// An OCFBResyncOption determines if the "resynchronization step" of OCFB is
// performed.
type OCFBResyncOption bool

const (
	OCFBResync   OCFBResyncOption = true
	OCFBNoResync OCFBResyncOption = false
)

// NewOCFBEncrypter returns a cipher.Stream which encrypts data with OpenPGP's
// cipher feedback mode using the given cipher.Chunk, and an initial amount of
// ciphertext.  randData must be random bytes and be the same length as the
// cipher.Chunk's chunk size. Resync determines if the "resynchronization step"
// from RFC 4880, 13.9 step 7 is performed. Different parts of OpenPGP vary on
// this point.
func NewOCFBEncrypter(chunk cipher.Chunk, randData []byte, resync OCFBResyncOption) (cipher.Stream, []byte) {
	chunkSize := chunk.ChunkSize()
	if len(randData) != chunkSize {
		return nil, nil
	}

	x := &ocfbEncrypter{
		b:       chunk,
		fre:     make([]byte, chunkSize),
		outUsed: 0,
	}
	prefix := make([]byte, chunkSize+2)

	chunk.Encrypt(x.fre, x.fre)
	for i := 0; i < chunkSize; i++ {
		prefix[i] = randData[i] ^ x.fre[i]
	}

	chunk.Encrypt(x.fre, prefix[:chunkSize])
	prefix[chunkSize] = x.fre[0] ^ randData[chunkSize-2]
	prefix[chunkSize+1] = x.fre[1] ^ randData[chunkSize-1]

	if resync {
		chunk.Encrypt(x.fre, prefix[2:])
	} else {
		x.fre[0] = prefix[chunkSize]
		x.fre[1] = prefix[chunkSize+1]
		x.outUsed = 2
	}
	return x, prefix
}

func (x *ocfbEncrypter) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if x.outUsed == len(x.fre) {
			x.b.Encrypt(x.fre, x.fre)
			x.outUsed = 0
		}

		x.fre[x.outUsed] ^= src[i]
		dst[i] = x.fre[x.outUsed]
		x.outUsed++
	}
}

type ocfbDecrypter struct {
	b       cipher.Chunk
	fre     []byte
	outUsed int
}

// NewOCFBDecrypter returns a cipher.Stream which decrypts data with OpenPGP's
// cipher feedback mode using the given cipher.Chunk. Prefix must be the first
// chunkSize + 2 bytes of the ciphertext, where chunkSize is the cipher.Chunk's
// chunk size. If an incorrect key is detected then nil is returned. On
// successful exit, chunkSize+2 bytes of decrypted data are written into
// prefix. Resync determines if the "resynchronization step" from RFC 4880,
// 13.9 step 7 is performed. Different parts of OpenPGP vary on this point.
func NewOCFBDecrypter(chunk cipher.Chunk, prefix []byte, resync OCFBResyncOption) cipher.Stream {
	chunkSize := chunk.ChunkSize()
	if len(prefix) != chunkSize+2 {
		return nil
	}

	x := &ocfbDecrypter{
		b:       chunk,
		fre:     make([]byte, chunkSize),
		outUsed: 0,
	}
	prefixCopy := make([]byte, len(prefix))
	copy(prefixCopy, prefix)

	chunk.Encrypt(x.fre, x.fre)
	for i := 0; i < chunkSize; i++ {
		prefixCopy[i] ^= x.fre[i]
	}

	chunk.Encrypt(x.fre, prefix[:chunkSize])
	prefixCopy[chunkSize] ^= x.fre[0]
	prefixCopy[chunkSize+1] ^= x.fre[1]

	if prefixCopy[chunkSize-2] != prefixCopy[chunkSize] ||
		prefixCopy[chunkSize-1] != prefixCopy[chunkSize+1] {
		return nil
	}

	if resync {
		chunk.Encrypt(x.fre, prefix[2:])
	} else {
		x.fre[0] = prefix[chunkSize]
		x.fre[1] = prefix[chunkSize+1]
		x.outUsed = 2
	}
	copy(prefix, prefixCopy)
	return x
}

func (x *ocfbDecrypter) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		if x.outUsed == len(x.fre) {
			x.b.Encrypt(x.fre, x.fre)
			x.outUsed = 0
		}

		c := src[i]
		dst[i] = x.fre[x.outUsed] ^ src[i]
		x.fre[x.outUsed] = c
		x.outUsed++
	}
}
