package md5

/*
#include "openssl/md5.h"
#cgo pkg-config: openssl
*/
import "C"
import (
	"hash"
	"unsafe"
)

// The blocksize of MD5 in bytes.
const BlockSize = 64

// The size of an MD5 checksum in bytes.
const Size = 16

type MD5Hash struct {
	md5 C.MD5_CTX
}

func (mh *MD5Hash) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.MD5_Update(&mh.md5, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		panic("problem updating hash")
	}
	return len(msg), nil
}
func (mh *MD5Hash) BlockSize() int {
	return C.MD5_DIGEST_LENGTH
}
func (mh *MD5Hash) Size() int {
	return C.MD5_DIGEST_LENGTH
}
func (mh *MD5Hash) Reset() {
	C.MD5_Init(&mh.md5)
}
func (mh *MD5Hash) Sum(b []byte) []byte {
	digest := make([]C.uchar, mh.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	// TODO perhaps we should think about runtime.SetFinalizer to free the context?
	s_tmp := C.MD5_CTX(mh.md5)
	if C.MD5_Final(&digest[0], &s_tmp) != 1 {
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

// Sum returns the MD5 checksum of the data.
func Sum(b []byte) [Size]byte {
	s := New()
	s.Reset()
	s.Write(b)
	var cs [Size]byte
	copy(cs[:], s.Sum(nil))
	return cs
}

// New returns a new hash.Hash computing the MD5 checksum.
func New() hash.Hash {
	h := new(MD5Hash)
	if C.MD5_Init(&h.md5) != 1 {
		panic("problem creating hash")
	}
	return h
}
