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
    if C.SHA384_Final(&digest[0], &self.sha) != 1 {
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
