package sha1

/*
#cgo pkg-config: openssl
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/sha.h"
*/
import "C"
import (
	"hash"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

const (
	// The size of a SHA1 checksum in bytes.
	Size = C.SHA_DIGEST_LENGTH

	// The blocksize of SHA1 in bytes.
	BlockSize = 64
)

type digest struct {
	ctx C.SHA_CTX
}

// New returns a new sha1 hash.Hash
// if the returned hash is nil, then make a call to sslerr.Error() to know
// what went wrong
func New() hash.Hash {
	d := new(digest)
	if C.SHA1_Init(&d.ctx) != 1 {
		return nil
	}
	return d
}

func (d *digest) Reset() {
	C.SHA1_Init(&d.ctx)
}

func (digest *digest) BlockSize() int { return BlockSize }

func (digest *digest) Size() int { return Size }

func (d *digest) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.SHA1_Update(&d.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		return 0, sslerr.Error()
	}
	return len(msg), nil
}

func (d *digest) Sum(b []byte) []byte {
	buf := make([]C.uchar, d.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	// TODO perhaps we should think about runtime.SetFinalizer to free the context?
	ctxTmp := C.SHA_CTX(d.ctx)
	if C.SHA1_Final(&buf[0], &ctxTmp) != 1 {
		return make([]byte, 0)
	}
	var result []byte
	if b != nil {
		result = make([]byte, 0)
	} else {
		result = b
	}
	for _, value := range buf {
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
