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
import "unsafe"
import "hash"

const BlockSize = 64
const Size = 32

// SHA256Hash is a wrapper around OpenSSL's SHA256_CTX
type SHA256Hash struct {
	sha C.SHA256_CTX
}

// New returns a new sha256 hash.Hash
func New() hash.Hash {
	hash := new(SHA256Hash)
	if C.SHA256_Init(&hash.sha) != 1 {
		panic("problem creating hash")
	}
	return hash
}

func (self *SHA256Hash) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.SHA256_Update(&self.sha, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		panic("problem updating hash")
	}
	return len(msg), nil
}
func (self *SHA256Hash) BlockSize() int {
	return C.SHA256_DIGEST_LENGTH
}
func (self *SHA256Hash) Size() int {
	return C.SHA256_DIGEST_LENGTH
}
func (self *SHA256Hash) Reset() {
	C.SHA256_Init(&self.sha)
}
func (self *SHA256Hash) Sum(b []byte) []byte {
	digest := make([]C.uchar, self.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	// TODO perhaps we should think about runtime.SetFinalizer to free the context?
	s_tmp := C.SHA256_CTX(self.sha)
	if C.SHA256_Final(&digest[0], &s_tmp) != 1 {
		panic("couldn't finalize digest")
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
