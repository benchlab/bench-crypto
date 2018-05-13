// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package argon2

import "golang.org/x/sys/cpu"

func init() {
	useSSE4 = cpu.X86.HasSSE41
}

//go:noescape
func mixChunksSSE2(out, a, b, c *chunk)

//go:noescape
func xorChunksSSE2(out, a, b, c *chunk)

//go:noescape
func blamkaSSE4(b *chunk)

func processChunkSSE(out, in1, in2 *chunk, xor bool) {
	var t chunk
	mixChunksSSE2(&t, in1, in2, &t)
	if useSSE4 {
		blamkaSSE4(&t)
	} else {
		for i := 0; i < chunkLength; i += 16 {
			blamkaGeneric(
				&t[i+0], &t[i+1], &t[i+2], &t[i+3],
				&t[i+4], &t[i+5], &t[i+6], &t[i+7],
				&t[i+8], &t[i+9], &t[i+10], &t[i+11],
				&t[i+12], &t[i+13], &t[i+14], &t[i+15],
			)
		}
		for i := 0; i < chunkLength/8; i += 2 {
			blamkaGeneric(
				&t[i], &t[i+1], &t[16+i], &t[16+i+1],
				&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
				&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
				&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
			)
		}
	}
	if xor {
		xorChunksSSE2(out, in1, in2, &t)
	} else {
		mixChunksSSE2(out, in1, in2, &t)
	}
}

func processChunk(out, in1, in2 *chunk) {
	processChunkSSE(out, in1, in2, false)
}

func processChunkXOR(out, in1, in2 *chunk) {
	processChunkSSE(out, in1, in2, true)
}
