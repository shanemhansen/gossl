// +build darwin dragonfly freebsd linux netbsd openbsd plan9 solaris

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
	//"../sslerr"
	"errors"
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
	var buf *C.uchar = (*C.uchar)(C.malloc(C.size_t(len(p))))
	defer C.free(unsafe.Pointer(buf))

	if C.RAND_bytes(buf, 255) == 1 {
		copy(p, C.GoBytes(unsafe.Pointer(buf), C.int(len(p))))
		return len(p), nil
	}
	return 0, errors.New("farts") // TODO read the error from SSL
	//errors.New(sslerr.SSLErrorMessage())
}

func defaultRandSeedFile() string {
	path := C.CString("")
	C.RAND_file_name(path, 1024)
	return C.GoString(path)
}

func Read(b []byte) (n int, err error) {
	r := reader{}
	return r.Read(b)
}
