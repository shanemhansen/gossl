// +build darwin dragonfly freebsd linux netbsd openbsd plan9 solaris

// Package rand implements a cryptographically secure pseudorandom number generator.
package rand

/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/rand.h"
#cgo pkg-config: openssl
*/
import "C"
import (
	"github.com/shanemhansen/gossl/sslerr"
	"io"
	"unsafe"
)

func init() {
	Reader = newReader()
}

func newReader() io.Reader {
	return &reader{}
}

type reader struct {
}

func (r *reader) Read(p []byte) (n int, err error) {
	var (
		p_len          = len(p)
		buf   *C.uchar = (*C.uchar)(C.malloc(C.size_t(p_len)))
	)
	defer C.free(unsafe.Pointer(buf))

	if C.RAND_bytes(buf, C.int(p_len)) == 1 {
		copy(p, C.GoBytes(unsafe.Pointer(buf), C.int(p_len)))
		return len(p), nil
	}
	return 0, sslerr.Error()
}

func defaultRandSeedFile() string {
	path := C.CString("")
	C.RAND_file_name(path, 1024)
	return C.GoString(path)
}

/*
Read is a helper function that calls Reader.Read using io.ReadFull.
On return, n == len(b) if and only if err == nil.
*/
func Read(b []byte) (n int, err error) {
	r := reader{}
	return r.Read(b)
}
