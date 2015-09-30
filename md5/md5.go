package md5

/*
#cgo pkg-config: openssl
#include "openssl/md5.h"
*/
import "C"
import (
	"hash"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

const (
	// The size of an MD5 checksum in bytes.
	Size = C.MD5_DIGEST_LENGTH

	// The blocksize of MD5 in bytes.
	BlockSize = 64
)

type digest struct {
	ctx C.MD5_CTX
}

func (d *digest) Reset() {
	C.MD5_Init(&d.ctx)
}

// New returns a new MD5 hash.Hash
// if the returned hash is empty, then make a call to sslerr.Error()
func New() hash.Hash {
	d := new(digest)
	if C.MD5_Init(&d.ctx) != 1 {
		return nil
	}
	return d
}

func (d *digest) BlockSize() int { return BlockSize }

func (d *digest) Size() int { return Size }

func (d *digest) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.MD5_Update(&d.ctx, unsafe.Pointer(C.CString(string(msg))), size) != 1 {
		return 0, sslerr.Error()
	}
	return len(msg), nil
}

func (d *digest) Sum(b []byte) []byte {
	buf := make([]C.uchar, d.Size())
	// make a copy of the pointer, so our context does not get freed.
	// this allows further writes.
	// TODO perhaps we should think about runtime.SetFinalizer to free the context?
	ctxTmp := C.MD5_CTX(d.ctx)
	if C.MD5_Final(&buf[0], &ctxTmp) != 1 {
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

// Sum returns the MD5 checksum of the data.
func Sum(b []byte) [Size]byte {
	s := New()
	s.Reset()
	s.Write(b)
	var cs [Size]byte
	copy(cs[:], s.Sum(nil))
	return cs
}
