package sha1

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

//various interface values copied to match crypro/sha1 interface.

const BlockSize = 64
const Size = 20

type SHA1Hash struct {
	sha C.SHA_CTX
}

// New returns a new sha1 hash.Hash
func New() hash.Hash {
	h := new(SHA1Hash)
	if C.SHA1_Init(&h.sha) != 1 {
		panic("problem creating hash")
	}
	return h
}

func (self *SHA1Hash) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.SHA1_Update(&self.sha, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		panic("problem updating hash")
	}
	return len(msg), nil
}
func (self *SHA1Hash) BlockSize() int {
	return C.SHA_DIGEST_LENGTH
}
func (self *SHA1Hash) Size() int {
	return C.SHA_DIGEST_LENGTH
}
func (self *SHA1Hash) Reset() {
	C.SHA1_Init(&self.sha)
}
func (self *SHA1Hash) Sum(b []byte) []byte {
	digest := make([]C.uchar, self.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	// TODO perhaps we should think about runtime.SetFinalizer to free the context?
	s_tmp := C.SHA_CTX(self.sha)
	if C.SHA1_Final(&digest[0], &s_tmp) != 1 {
		// TODO maybe not panic here?
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

func Sum(b []byte) [Size]byte {
	s := New()
	s.Reset()
	s.Write(b)
	var cs [Size]byte
	copy(cs[:], s.Sum(nil))
	return cs
}
