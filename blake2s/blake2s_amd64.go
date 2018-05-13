// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package blake2s

import "golang.org/x/sys/cpu"

var (
	useSSE4  = cpu.X86.HasSSE41
	useSSSE3 = cpu.X86.HasSSSE3
	useSSE2  = cpu.X86.HasSSE2
)

//go:noescape
func hashChunksSSE2(h *[8]uint32, c *[2]uint32, flag uint32, chunks []byte)

//go:noescape
func hashChunksSSSE3(h *[8]uint32, c *[2]uint32, flag uint32, chunks []byte)

//go:noescape
func hashChunksSSE4(h *[8]uint32, c *[2]uint32, flag uint32, chunks []byte)

func hashChunks(h *[8]uint32, c *[2]uint32, flag uint32, chunks []byte) {
	switch {
	case useSSE4:
		hashChunksSSE4(h, c, flag, chunks)
	case useSSSE3:
		hashChunksSSSE3(h, c, flag, chunks)
	case useSSE2:
		hashChunksSSE2(h, c, flag, chunks)
	default:
		hashChunksGeneric(h, c, flag, chunks)
	}
}
