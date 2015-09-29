// Package sha256 implements the SHA224 and SHA256 hash algorithms
// in FIPS 180-2.
package sha256

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
	"hash"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

const (
	// The size of a SHA256 checksum in bytes.
	Size = C.SHA256_DIGEST_LENGTH

	// The size of a SHA224 checksum in bytes.
	Size224 = C.SHA224_DIGEST_LENGTH

	// The blocksize of SHA256 and SHA224 in bytes.
	BlockSize = 64
)

// digest is a wrapper around OpenSSL's SHA256_CTX
type digest struct {
	ctx   C.SHA256_CTX
	is224 bool
}

func (d *digest) Reset() {
	if d.is224 {
		C.SHA224_Init(&d.ctx)
		return
	}
	C.SHA256_Init(&d.ctx)
}

// New returns a new sha256 hash.Hash
// if the returned hash is empty, then make a call to sslerr.Error()
func New() hash.Hash {
	d := new(digest)
	if C.SHA256_Init(&d.ctx) != 1 {
		return nil
	}
	return d
}

func New224() hash.Hash {
	d := new(digest)
	d.is224 = true
	if C.SHA224_Init(&d.ctx) != 1 {
		return nil
	}
	return d
}

func (d *digest) Size() int {
	if d.is224 {
		return Size224
	}
	return Size
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Write(msg []byte) (n int, err error) {
	mlen := len(msg)
	size := C.size_t(mlen)
	if d.is224 {
		if C.SHA224_Update(&d.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
			return 0, sslerr.Error()
		}
		return mlen, nil
	}
	if C.SHA256_Update(&d.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		return 0, sslerr.Error()
	}
	return mlen, nil
}

// if the returned array is empty, then make a call to sslerr.Error()
func (d *digest) Sum(b []byte) []byte {
	buf := make([]C.uchar, d.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	ctxTmp := C.SHA256_CTX(d.ctx)
	if d.is224 {
		if C.SHA224_Final(&buf[0], &ctxTmp) != 1 {
			return make([]byte, 0)
		}
	} else {
		if C.SHA256_Final(&buf[0], &ctxTmp) != 1 {
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

// Sum256 returns the SHA256 checksum of the data.
func Sum256(data []byte) (sum256 [Size]byte) {
	d := New()
	d.Write(data)
	var cs [Size]byte
	copy(cs[:], d.Sum(nil))
	return cs
}

// Sum224 returns the SHA224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
	d := New224()
	d.Write(data)
	var cs [Size224]byte
	copy(cs[:], d.Sum(nil))
	return cs
}
