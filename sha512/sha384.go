package sha512

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

type SHA384Hash struct {
	sha C.SHA512_CTX
}

// New returns a new sha256 hash.Hash
func New384() hash.Hash {
	hash := new(SHA384Hash)
	if C.SHA384_Init(&hash.sha) != 1 {
		panic("problem creating hash")
	}
	return hash
}

func (self *SHA384Hash) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.SHA384_Update(&self.sha, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		panic("problem updating hash")
	}
	return len(msg), nil
}
func (self *SHA384Hash) BlockSize() int {
	return C.SHA384_DIGEST_LENGTH
}
func (self *SHA384Hash) Size() int {
	return C.SHA384_DIGEST_LENGTH
}
func (self *SHA384Hash) Reset() {
	C.SHA384_Init(&self.sha)
}
func (self *SHA384Hash) Sum(b []byte) []byte {
	digest := make([]C.uchar, self.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	// TODO perhaps we should think about runtime.SetFinalizer to free the context?
	s_tmp := C.SHA512_CTX(self.sha)
	if C.SHA384_Final(&digest[0], &s_tmp) != 1 {
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

// Sum384 returns the SHA384 checksum of the data
func Sum384(data []byte) (sum384 [Size384]byte) {
	s := New384()
	s.Reset()
	s.Write(data)
	var cs [Size384]byte
	copy(cs[:], s.Sum(nil))
	return cs
}
