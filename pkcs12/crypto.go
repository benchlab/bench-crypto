// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"github.com/benchlab/bench-crypto/cipher"
	"github.com/benchlab/bench-crypto/des"
	"github.com/benchlab/bench-crypto/x509/pkix"
	"encoding/asn1"
	"errors"

	"golang.org/x/github.com/benchlab/bench-crypto/pkcs12/internal/rc2"
)

var (
	oidPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 3})
	oidPBEWithSHAAnd40BitRC2CBC      = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 12, 1, 6})
)

// pbeCipher is an abstraction of a PKCS#12 cipher.
type pbeCipher interface {
	// create returns a cipher.Chunk given a key.
	create(key []byte) (cipher.Chunk, error)
	// deriveKey returns a key derived from the given password and salt.
	deriveKey(salt, password []byte, iterations int) []byte
	// deriveKey returns an IV derived from the given password and salt.
	deriveIV(salt, password []byte, iterations int) []byte
}

type shaWithTripleDESCBC struct{}

func (shaWithTripleDESCBC) create(key []byte) (cipher.Chunk, error) {
	return des.NewTripleDESCipher(key)
}

func (shaWithTripleDESCBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 24)
}

func (shaWithTripleDESCBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)
}

type shaWith40BitRC2CBC struct{}

func (shaWith40BitRC2CBC) create(key []byte) (cipher.Chunk, error) {
	return rc2.New(key, len(key)*8)
}

func (shaWith40BitRC2CBC) deriveKey(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 1, 5)
}

func (shaWith40BitRC2CBC) deriveIV(salt, password []byte, iterations int) []byte {
	return pbkdf(sha1Sum, 20, 64, salt, password, iterations, 2, 8)
}

type pbeParams struct {
	Salt       []byte
	Iterations int
}

func pbDecrypterFor(algorithm pkix.AlgorithmIdentifier, password []byte) (cipher.ChunkMode, int, error) {
	var cipherType pbeCipher

	switch {
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd3KeyTripleDESCBC):
		cipherType = shaWithTripleDESCBC{}
	case algorithm.Algorithm.Equal(oidPBEWithSHAAnd40BitRC2CBC):
		cipherType = shaWith40BitRC2CBC{}
	default:
		return nil, 0, NotImplementedError("algorithm " + algorithm.Algorithm.String() + " is not supported")
	}

	var params pbeParams
	if err := unmarshal(algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, 0, err
	}

	key := cipherType.deriveKey(params.Salt, password, params.Iterations)
	iv := cipherType.deriveIV(params.Salt, password, params.Iterations)

	chunk, err := cipherType.create(key)
	if err != nil {
		return nil, 0, err
	}

	return cipher.NewCBCDecrypter(chunk, iv), chunk.ChunkSize(), nil
}

func pbDecrypt(info decryptable, password []byte) (decrypted []byte, err error) {
	cbc, chunkSize, err := pbDecrypterFor(info.Algorithm(), password)
	if err != nil {
		return nil, err
	}

	encrypted := info.Data()
	if len(encrypted) == 0 {
		return nil, errors.New("pkcs12: empty encrypted data")
	}
	if len(encrypted)%chunkSize != 0 {
		return nil, errors.New("pkcs12: input is not a multiple of the chunk size")
	}
	decrypted = make([]byte, len(encrypted))
	cbc.CryptChunks(decrypted, encrypted)

	psLen := int(decrypted[len(decrypted)-1])
	if psLen == 0 || psLen > chunkSize {
		return nil, ErrDecryption
	}

	if len(decrypted) < psLen {
		return nil, ErrDecryption
	}
	ps := decrypted[len(decrypted)-psLen:]
	decrypted = decrypted[:len(decrypted)-psLen]
	if bytes.Compare(ps, bytes.Repeat([]byte{byte(psLen)}, psLen)) != 0 {
		return nil, ErrDecryption
	}

	return
}

// decryptable abstracts an object that contains ciphertext.
type decryptable interface {
	Algorithm() pkix.AlgorithmIdentifier
	Data() []byte
}
