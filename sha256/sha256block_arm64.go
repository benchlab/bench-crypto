// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha256

import "golang.org/x/sys/cpu"

var k = _K

var hasSHA2 = cpu.ARM64.HasSHA2

//go:noescape
func sha256chunk(h []uint32, p []byte, k []uint32)

func chunk(dig *digest, p []byte) {
	if !hasSHA2 {
		chunkGeneric(dig, p)
	} else {
		h := dig.h[:]
		sha256chunk(h, p, k)
	}
}
