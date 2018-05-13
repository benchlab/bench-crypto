// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// CFB (Cipher Feedback) Mode.

package cipher

type cfb struct {
	b       Chunk
	next    []byte
	out     []byte
	outUsed int

	decrypt bool
}

func (x *cfb) XORKeyStream(dst, src []byte) {
	for len(src) > 0 {
		if x.outUsed == len(x.out) {
			x.b.Encrypt(x.out, x.next)
			x.outUsed = 0
		}

		if x.decrypt {
			// We can precompute a larger segment of the
			// keystream on decryption. This will allow
			// larger batches for xor, and we should be
			// able to match CTR/OFB performance.
			copy(x.next[x.outUsed:], src)
		}
		n := xorBytes(dst, src, x.out[x.outUsed:])
		if !x.decrypt {
			copy(x.next[x.outUsed:], dst)
		}
		dst = dst[n:]
		src = src[n:]
		x.outUsed += n
	}
}

// NewCFBEncrypter returns a Stream which encrypts with cipher feedback mode,
// using the given Chunk. The iv must be the same length as the Chunk's chunk
// size.
func NewCFBEncrypter(chunk Chunk, iv []byte) Stream {
	return newCFB(chunk, iv, false)
}

// NewCFBDecrypter returns a Stream which decrypts with cipher feedback mode,
// using the given Chunk. The iv must be the same length as the Chunk's chunk
// size.
func NewCFBDecrypter(chunk Chunk, iv []byte) Stream {
	return newCFB(chunk, iv, true)
}

func newCFB(chunk Chunk, iv []byte, decrypt bool) Stream {
	chunkSize := chunk.ChunkSize()
	if len(iv) != chunkSize {
		// stack trace will indicate whether it was de or encryption
		panic("cipher.newCFB: IV length must equal chunk size")
	}
	x := &cfb{
		b:       chunk,
		out:     make([]byte, chunkSize),
		next:    make([]byte, chunkSize),
		outUsed: chunkSize,
		decrypt: decrypt,
	}
	copy(x.next, iv)

	return x
}
