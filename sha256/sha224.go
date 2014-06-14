package sha256

//routines for computing a sha224 hash

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

// The size of the SHA224 hash digest
const Size224 = 28

// sha224Hash is a wrapper around OpenSSL's SHA256_CTX (that's not a typo)
type sha224Hash struct {
	ctx C.SHA256_CTX
}

// New returns a new sha224 hash.Hash
// if the returned hash is empty, then make a call to sslerr.Error()
func New224() hash.Hash {
	hash := new(sha224Hash)
	if C.SHA224_Init(&hash.ctx) != 1 {
		return nil
	}
	return hash
}

func (h *sha224Hash) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.SHA224_Update(&h.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		return len(msg), sslerr.Error()
	}
	return len(msg), nil
}
func (h *sha224Hash) BlockSize() int {
	return C.SHA224_DIGEST_LENGTH
}
func (h *sha224Hash) Size() int {
	return C.SHA224_DIGEST_LENGTH
}
func (h *sha224Hash) Reset() {
	C.SHA224_Init(&h.ctx)
}

// if the returned array is empty, then make a call to sslerr.Error()
func (h *sha224Hash) Sum(b []byte) []byte {
	digest := make([]C.uchar, h.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	s_tmp := C.SHA256_CTX(h.ctx)
	if C.SHA224_Final(&digest[0], &s_tmp) != 1 {
		return []byte{}
	}
	var result []byte
	if b != nil {
		result = make([]byte, len(b)+len(digest))
		for index := range b {
			result[index] = b[index]
		}
	} else {
		result = make([]byte, len(digest))
	}
	for index, value := range digest {
		result[len(b)+index] = byte(value)
	}
	return result
}

// Sum224 returns the SHA224 checksum of the data.
func Sum224(data []byte) (sum224 [Size224]byte) {
	h := New224()
	h.Write(data)
	var cs [Size224]byte
	copy(cs[:], h.Sum(nil))
	return cs
}
