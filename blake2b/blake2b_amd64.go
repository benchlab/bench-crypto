// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !go1.7,amd64,!gccgo,!appengine

package blake2b

import "golang.org/x/sys/cpu"

func init() {
	useSSE4 = cpu.X86.HasSSE41
}

//go:noescape
func hashChunksSSE4(h *[8]uint64, c *[2]uint64, flag uint64, chunks []byte)

func hashChunks(h *[8]uint64, c *[2]uint64, flag uint64, chunks []byte) {
	if useSSE4 {
		hashChunksSSE4(h, c, flag, chunks)
	} else {
		hashChunksGeneric(h, c, flag, chunks)
	}
}
