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
	"../sslerr"
	"errors"
	"io"
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
	return
}

func defaultRandSeedFile() string {
	path := C.CString("")
	C.RAND_file_name(path, 1024)
	return C.GoString(path)
}

func Read(b []byte) (n int, err error) {
	buf := make([]C.uchar, len(b))
	ret := C.RAND_bytes(buf, len(buf))
	if ret != 1 {
		errors.New(sslerr.SSLErrorMessage())
	}
	return nil
}
