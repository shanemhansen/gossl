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
//some constants to match the interface of the official crypto/sha256
const BlockSize = 64
const Size = 32


type SHA256Hash struct {
    sha C.SHA256_CTX
}

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
    if C.SHA256_Final(&digest[0], &self.sha) != 1 {
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
