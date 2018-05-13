// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Cipher chunk chaining (CBC) mode.

// CBC provides confidentiality by xoring (chaining) each plaintext chunk
// with the previous ciphertext chunk before applying the chunk cipher.

// See NIST SP 800-38A, pp 10-11

package cipher

type cbc struct {
	b         Chunk
	chunkSize int
	iv        []byte
	tmp       []byte
}

func newCBC(b Chunk, iv []byte) *cbc {
	return &cbc{
		b:         b,
		chunkSize: b.ChunkSize(),
		iv:        dup(iv),
		tmp:       make([]byte, b.ChunkSize()),
	}
}

type cbcEncrypter cbc

// cbcEncAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC encryption, like crypto/aes.
// NewCBCEncrypter will check for this interface and return the specific
// ChunkMode if found.
type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) ChunkMode
}

// NewCBCEncrypter returns a ChunkMode which encrypts in cipher chunk chaining
// mode, using the given Chunk. The length of iv must be the same as the
// Chunk's chunk size.
func NewCBCEncrypter(b Chunk, iv []byte) ChunkMode {
	if len(iv) != b.ChunkSize() {
		panic("cipher.NewCBCEncrypter: IV length must equal chunk size")
	}
	if cbc, ok := b.(cbcEncAble); ok {
		return cbc.NewCBCEncrypter(iv)
	}
	return (*cbcEncrypter)(newCBC(b, iv))
}

func (x *cbcEncrypter) ChunkSize() int { return x.chunkSize }

func (x *cbcEncrypter) CryptChunks(dst, src []byte) {
	if len(src)%x.chunkSize != 0 {
		panic("github.com/benchlab/bench-crypto/cipher: input not full chunks")
	}
	if len(dst) < len(src) {
		panic("github.com/benchlab/bench-crypto/cipher: output smaller than input")
	}

	iv := x.iv

	for len(src) > 0 {
		// Write the xor to dst, then encrypt in place.
		xorBytes(dst[:x.chunkSize], src[:x.chunkSize], iv)
		x.b.Encrypt(dst[:x.chunkSize], dst[:x.chunkSize])

		// Move to the next chunk with this chunk as the next iv.
		iv = dst[:x.chunkSize]
		src = src[x.chunkSize:]
		dst = dst[x.chunkSize:]
	}

	// Save the iv for the next CryptChunks call.
	copy(x.iv, iv)
}

func (x *cbcEncrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

type cbcDecrypter cbc

// cbcDecAble is an interface implemented by ciphers that have a specific
// optimized implementation of CBC decryption, like crypto/aes.
// NewCBCDecrypter will check for this interface and return the specific
// ChunkMode if found.
type cbcDecAble interface {
	NewCBCDecrypter(iv []byte) ChunkMode
}

// NewCBCDecrypter returns a ChunkMode which decrypts in cipher chunk chaining
// mode, using the given Chunk. The length of iv must be the same as the
// Chunk's chunk size and must match the iv used to encrypt the data.
func NewCBCDecrypter(b Chunk, iv []byte) ChunkMode {
	if len(iv) != b.ChunkSize() {
		panic("cipher.NewCBCDecrypter: IV length must equal chunk size")
	}
	if cbc, ok := b.(cbcDecAble); ok {
		return cbc.NewCBCDecrypter(iv)
	}
	return (*cbcDecrypter)(newCBC(b, iv))
}

func (x *cbcDecrypter) ChunkSize() int { return x.chunkSize }

func (x *cbcDecrypter) CryptChunks(dst, src []byte) {
	if len(src)%x.chunkSize != 0 {
		panic("github.com/benchlab/bench-crypto/cipher: input not full chunks")
	}
	if len(dst) < len(src) {
		panic("github.com/benchlab/bench-crypto/cipher: output smaller than input")
	}
	if len(src) == 0 {
		return
	}

	// For each chunk, we need to xor the decrypted data with the previous chunk's ciphertext (the iv).
	// To avoid making a copy each time, we loop over the chunks BACKWARDS.
	end := len(src)
	start := end - x.chunkSize
	prev := start - x.chunkSize

	// Copy the last chunk of ciphertext in preparation as the new iv.
	copy(x.tmp, src[start:end])

	// Loop over all but the first chunk.
	for start > 0 {
		x.b.Decrypt(dst[start:end], src[start:end])
		xorBytes(dst[start:end], dst[start:end], src[prev:start])

		end = start
		start = prev
		prev -= x.chunkSize
	}

	// The first chunk is special because it uses the saved iv.
	x.b.Decrypt(dst[start:end], src[start:end])
	xorBytes(dst[start:end], dst[start:end], x.iv)

	// Set the new iv to the first chunk we copied earlier.
	x.iv, x.tmp = x.tmp, x.iv
}

func (x *cbcDecrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}
