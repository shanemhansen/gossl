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
//various interface values copied to match crypro/sha512 interface.

const BlockSize = 128
const Size = 64
const Size384 = 48

type SHA512Hash struct {
    sha C.SHA512_CTX
}
// New returns a new sha256 hash.Hash
func New() hash.Hash {
    hash := new(SHA512Hash)
    if C.SHA512_Init(&hash.sha) != 1 {
        panic("problem creating hash")
    }
    return hash
}

func (self *SHA512Hash) Write(msg []byte) (n int, err error) {
    size := C.size_t(len(msg))
    if C.SHA512_Update(&self.sha, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
        panic("problem updating hash")
    }
    return len(msg), nil
}
func (self *SHA512Hash) BlockSize() int {
    return C.SHA512_DIGEST_LENGTH
}
func (self *SHA512Hash) Size() int {
    return C.SHA512_DIGEST_LENGTH
}
func (self *SHA512Hash) Reset() {
    C.SHA512_Init(&self.sha)
}
func (self *SHA512Hash) Sum(b []byte) []byte {
    digest := make([]C.uchar, self.Size())
    if C.SHA512_Final(&digest[0], &self.sha) != 1 {
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
