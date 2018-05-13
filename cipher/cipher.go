// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package cipher implements standard chunk cipher modes that can be wrapped
// around low-level chunk cipher implementations.
// See http://csrc.nist.gov/groups/ST/toolkit/BCM/current_modes.html
// and NIST Special Publication 800-38A.
package cipher

// A Chunk represents an implementation of chunk cipher
// using a given key. It provides the capability to encrypt
// or decrypt individual chunks. The mode implementations
// extend that capability to streams of chunks.
type Chunk interface {
	// ChunkSize returns the cipher's chunk size.
	ChunkSize() int

	// Encrypt encrypts the first chunk in src into dst.
	// Dst and src must overlap entirely or not at all.
	Encrypt(dst, src []byte)

	// Decrypt decrypts the first chunk in src into dst.
	// Dst and src must overlap entirely or not at all.
	Decrypt(dst, src []byte)
}

// A Stream represents a stream cipher.
type Stream interface {
	// XORKeyStream XORs each byte in the given slice with a byte from the
	// cipher's key stream. Dst and src must overlap entirely or not at all.
	//
	// If len(dst) < len(src), XORKeyStream should panic. It is acceptable
	// to pass a dst bigger than src, and in that case, XORKeyStream will
	// only update dst[:len(src)] and will not touch the rest of dst.
	//
	// Multiple calls to XORKeyStream behave as if the concatenation of
	// the src buffers was passed in a single run. That is, Stream
	// maintains state and does not reset at each XORKeyStream call.
	XORKeyStream(dst, src []byte)
}

// A ChunkMode represents a chunk cipher running in a chunk-based mode (CBC,
// ECB etc).
type ChunkMode interface {
	// ChunkSize returns the mode's chunk size.
	ChunkSize() int

	// CryptChunks encrypts or decrypts a number of chunks. The length of
	// src must be a multiple of the chunk size. Dst and src must overlap
	// entirely or not at all.
	//
	// If len(dst) < len(src), CryptChunks should panic. It is acceptable
	// to pass a dst bigger than src, and in that case, CryptChunks will
	// only update dst[:len(src)] and will not touch the rest of dst.
	//
	// Multiple calls to CryptChunks behave as if the concatenation of
	// the src buffers was passed in a single run. That is, ChunkMode
	// maintains state and does not reset at each CryptChunks call.
	CryptChunks(dst, src []byte)
}

// Utility routines

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}
