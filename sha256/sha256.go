// Package sha256 implements the SHA224 and SHA256 hash algorithms
// in FIPS 180-2.
package sha256

/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/sha.h"
#cgo pkg-config: openssl


*/
import "C"
import (
	"github.com/shanemhansen/gossl/sslerr"
	"hash"
	"unsafe"
)

const BlockSize = 64
const Size = 32

// sha256Hash is a wrapper around OpenSSL's SHA256_CTX
type sha256Hash struct {
	ctx C.SHA256_CTX
}

// New returns a new sha256 hash.Hash
// if the returned hash is empty, then make a call to sslerr.Error()
func New() hash.Hash {
	h := new(sha256Hash)
	if C.SHA256_Init(&h.ctx) != 1 {
		return nil
	}
	return h
}

func (h *sha256Hash) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.SHA256_Update(&h.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		return len(msg), sslerr.Error()
	}
	return len(msg), nil
}
func (h *sha256Hash) BlockSize() int {
	return C.SHA256_DIGEST_LENGTH
}
func (h *sha256Hash) Size() int {
	return C.SHA256_DIGEST_LENGTH
}
func (h *sha256Hash) Reset() {
	C.SHA256_Init(&h.ctx)
}

// if the returned array is empty, then make a call to sslerr.Error()
func (h *sha256Hash) Sum(b []byte) []byte {
	digest := make([]C.uchar, h.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	s_tmp := C.SHA256_CTX(h.ctx)
	if C.SHA256_Final(&digest[0], &s_tmp) != 1 {
		return []byte{}
	}
	var result []byte
	if b != nil {
		result = make([]byte, 0)
	} else {
		result = b
	}
	for _, value := range digest {
		result = append(result, byte(value))
	}
	return result
}

// Sum256 returns the SHA256 checksum of the data.
func Sum256(data []byte) [Size]byte {
	h := New()
	h.Write(data)
	var cs [Size]byte
	copy(cs[:], h.Sum(nil))
	return cs
}
