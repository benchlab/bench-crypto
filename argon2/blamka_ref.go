// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !amd64 appengine gccgo

package argon2

func processChunk(out, in1, in2 *chunk) {
	processChunkGeneric(out, in1, in2, false)
}

func processChunkXOR(out, in1, in2 *chunk) {
	processChunkGeneric(out, in1, in2, true)
}
