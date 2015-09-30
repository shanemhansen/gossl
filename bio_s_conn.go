package gossl

/*
#cgo pkg-config: openssl
#include "openssl/ssl.h"
#include "openssl/err.h"
extern void go_conn_put_error(const char*);
extern void set_errno(int);
*/
import "C"
import "io"
import "unsafe"
import "reflect"
import "syscall"
import "fmt"
import "net"

var _ = fmt.Println

//export go_conn_bio_write
func go_conn_bio_write(bio *C.BIO, buf *C.char, num C.int) C.int {
	var conn *Conn = (*Conn)(bio.ptr)
	var size int = int(num)
	data := GoSliceFromCString(buf, size)
	n, err := conn.conn.Write(data)
	if err != nil && err != io.EOF {
		//We expect either a syscall error
		//or a netOp error wrapping a syscall error
	TESTERR:
		switch err.(type) {
		case syscall.Errno:
			C.set_errno(C.int(err.(syscall.Errno)))
		case *net.OpError:
			err = err.(*net.OpError).Err
			break TESTERR
		}
		return C.int(-1)
	}
	return C.int(n)
}

//export go_conn_bio_read
func go_conn_bio_read(bio *C.BIO, buf *C.char, num C.int) C.int {
	var conn *Conn = (*Conn)(bio.ptr)
	var size int = int(num)
	data := GoSliceFromCString(buf, size)
	n, err := conn.conn.Read(data)
	if err == nil {
		return C.int(n)
	}
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return 0
	}
	//We expect either a syscall error
	//or a netOp error wrapping a syscall error
TESTERR:
	switch err.(type) {
	case syscall.Errno:
		C.set_errno(C.int(err.(syscall.Errno)))
	case *net.OpError:
		err = err.(*net.OpError).Err
		break TESTERR
	}
	return C.int(-1)
}

//export go_conn_bio_new
func go_conn_bio_new(bio *C.BIO) C.int {
	//we are initializing here
	bio.init = C.int(1)
	//see mem_new()
	bio.num = C.int(-1)
	bio.ptr = nil
	bio.flags = C.BIO_FLAGS_READ | C.BIO_FLAGS_WRITE
	return C.int(1)
}

//export go_conn_bio_free
func go_conn_bio_free(bio *C.BIO) C.int {
	var conn *Conn = (*Conn)(bio.ptr)
	conn.conn.Close()
	if C.int(bio.shutdown) != 0 {
		bio.ptr = nil
		bio.flags = 0
		bio.init = 0
	}
	return C.int(1)
}

//export go_conn_bio_ctrl
func go_conn_bio_ctrl(bio *C.BIO, cmd C.int, num C.long, ptr unsafe.Pointer) C.long {
	//always return operation not supported
	//http://www.openssl.org/docs/crypto/BIO_ctrl.html
	return C.long(1)
}

// Provides a zero copy interface for returning a go slice backed by a c array.
func GoSliceFromCString(cArray *C.char, size int) (cslice []byte) {
	//See http://code.google.com/p/go-wiki/wiki/cgo
	//It turns out it's really easy to
	//make a string from a *C.char and vise versa.
	//not so easy to write to a c array.
	sliceHeader := (*reflect.SliceHeader)((unsafe.Pointer(&cslice)))
	sliceHeader.Cap = size
	sliceHeader.Len = size
	sliceHeader.Data = uintptr(unsafe.Pointer(cArray))
	return
}
