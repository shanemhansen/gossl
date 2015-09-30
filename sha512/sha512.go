package sha512

/*
#cgo pkg-config: openssl
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/sha.h"
*/
import "C"
import (
	"crypto"
	"hash"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

const (
	// Size is the size, in bytes, of a SHA-512 checksum.
	Size = C.SHA512_DIGEST_LENGTH

	// Size384 is the size, in bytes, of a SHA-384 checksum.
	Size384 = C.SHA384_DIGEST_LENGTH

	// BlockSize is the block size, in bytes, of the SHA-512/224,
	// SHA-512/256, SHA-384 and SHA-512 hash functions.
	BlockSize = 128
)

// digest is a wrapper around OpenSSL's SHA512_CTX
type digest struct {
	ctx      C.SHA512_CTX
	function crypto.Hash
}

func (d *digest) Reset() {
	switch d.function {
	case crypto.SHA384:
		C.SHA384_Init(&d.ctx)
	default:
		C.SHA512_Init(&d.ctx)
	}
}

// New returns a new sha512 hash.Hash
// if the returned hash is empty, then make a call to sslerr.Error()
func New() hash.Hash {
	d := new(digest)
	d.function = crypto.SHA512
	if C.SHA512_Init(&d.ctx) != 1 {
		return nil
	}
	return d
}

// New returns a new sha384 hash.Hash
// if the returned hash is empty, then make a call to sslerr.Error()
func New384() hash.Hash {
	d := new(digest)
	d.function = crypto.SHA384
	if C.SHA384_Init(&d.ctx) != 1 {
		return nil
	}
	return d
}

func (d *digest) Size() int {
	switch d.function {
	case crypto.SHA384:
		return Size384
	default:
		return Size
	}
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(msg []byte) (n int, err error) {
	mlen := len(msg)
	size := C.size_t(mlen)
	switch d.function {
	case crypto.SHA384:
		if C.SHA384_Update(&d.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
			return 0, sslerr.Error()
		}
		return mlen, nil
	default:
		if C.SHA512_Update(&d.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
			return 0, sslerr.Error()
		}
		return mlen, nil
	}
}

func (d *digest) Sum(b []byte) []byte {
	buf := make([]C.uchar, d.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	// TODO perhaps we should think about runtime.SetFinalizer to free the context?
	ctxTmp := C.SHA512_CTX(d.ctx)
	switch d.function {
	case crypto.SHA384:
		if C.SHA384_Final(&buf[0], &ctxTmp) != 1 {
			return make([]byte, 0)
		}
	default:
		if C.SHA512_Final(&buf[0], &ctxTmp) != 1 {
			return make([]byte, 0)
		}
	}
	var result []byte
	if b != nil {
		result = make([]byte, 0)
	} else {
		result = b
	}
	for _, value := range buf {
		result = append(result, byte(value))
	}
	return result
}

// Sum512 returns the SHA512 checksum of the data.
func Sum512(data []byte) [Size]byte {
	s := New()
	s.Reset()
	s.Write(data)
	var cs [Size]byte
	copy(cs[:], s.Sum(nil))
	return cs
}

// Sum384 returns the SHA384 checksum of the data
func Sum384(data []byte) (sum384 [Size384]byte) {
	s := New384()
	s.Reset()
	s.Write(data)
	var cs [Size384]byte
	copy(cs[:], s.Sum(nil))
	return cs
}
