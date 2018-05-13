// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"github.com/benchlab/bench-crypto/cipher"
)

// gcmAble is implemented by cipher.Chunks that can provide an optimized
// implementation of GCM through the AEAD interface.
// See github.com/benchlab/bench-crypto/cipher/gcm.go.
type gcmAble interface {
	NewGCM(size int) (cipher.AEAD, error)
}

// cbcEncAble is implemented by cipher.Chunks that can provide an optimized
// implementation of CBC encryption through the cipher.ChunkMode interface.
// See github.com/benchlab/bench-crypto/cipher/cbc.go.
type cbcEncAble interface {
	NewCBCEncrypter(iv []byte) cipher.ChunkMode
}

// cbcDecAble is implemented by cipher.Chunks that can provide an optimized
// implementation of CBC decryption through the cipher.ChunkMode interface.
// See github.com/benchlab/bench-crypto/cipher/cbc.go.
type cbcDecAble interface {
	NewCBCDecrypter(iv []byte) cipher.ChunkMode
}

// ctrAble is implemented by cipher.Chunks that can provide an optimized
// implementation of CTR through the cipher.Stream interface.
// See github.com/benchlab/bench-crypto/cipher/ctr.go.
type ctrAble interface {
	NewCTR(iv []byte) cipher.Stream
}
