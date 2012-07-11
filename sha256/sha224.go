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
import "unsafe"
import "hash"

// The size of the SHA224 hash digest
const Size224 = 28

// SHA224Hash is a wrapper around OpenSSL's SHA256_CTX (that's not a typo)
type SHA224Hash struct {
    sha C.SHA256_CTX
}

// New returns a new sha224 hash.Hash
func New224() hash.Hash {
    hash := new(SHA224Hash)
    if C.SHA224_Init(&hash.sha) != 1 {
        panic("problem creating hash")
    }
    return hash
}

func (self *SHA224Hash) Write(msg []byte) (n int, err error) {
    size := C.size_t(len(msg))
    if C.SHA224_Update(&self.sha, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
        panic("problem updating hash")
    }
    return len(msg), nil
}
func (self *SHA224Hash) BlockSize() int {
    return C.SHA224_DIGEST_LENGTH
}
func (self *SHA224Hash) Size() int {
    return C.SHA224_DIGEST_LENGTH
}
func (self *SHA224Hash) Reset() {
    C.SHA224_Init(&self.sha)
}
func (self *SHA224Hash) Sum(b []byte) []byte {
    digest := make([]C.uchar, self.Size())
    if C.SHA224_Final(&digest[0], &self.sha) != 1 {
        panic("couldn't finalize digest")
    }
    var result []byte
    if b != nil {
        result = make([]byte, len(b)+len(digest))
        for index:= range b {
            result[index] = b[index]
        }
    } else {
        result = make([]byte, len(digest))
    }
    for index, value := range digest {
        result[len(b) + index] = byte(value)
    }
    return result
}
