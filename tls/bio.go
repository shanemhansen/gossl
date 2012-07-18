package tls
/*
#cgo pkg-config: openssl
#include "openssl/ssl.h"
#include "openssl/err.h"
extern BIO_METHOD* BIO_s_conn(void);
extern void go_conn_put_error(const char*);
*/
import "C"
import "io"
import "fmt"
import "unsafe"
import "reflect"

var library_code C.int = C.ERR_get_next_error_library()

type BIO struct {
    c_bio *C.BIO
    conn *Conn
}
//Create a BIO from the existing connection
func New(conn *Conn) *BIO {
    self := &BIO{c_bio:C.BIO_new(C.BIO_s_conn())}
    self.conn = conn
    self.c_bio.ptr = unsafe.Pointer(self)
    return self
}
//export go_conn_bio_write
func go_conn_bio_write(bio *C.BIO, buf *C.char, num C.int) C.int {
    var conn *Conn = ((*BIO)(bio.ptr)).conn
    var size int = int(num)
    data := GoSliceFromCString(buf, size)
    n, err := conn.conn.Write(data)
    //See http://code.google.com/p/go-wiki/wiki/cgo
    if err != nil && err != io.EOF {
        //return Error to openssl
        C.ERR_put_error(library_code, 0, 0, C.CString("go-ssl/tls/bio.go"), 37)
        C.go_conn_put_error(C.CString(fmt.Sprintf("%s", err)))
        return C.int(-1)
    }
    return C.int(n)
}
//export go_conn_bio_read
func go_conn_bio_read(bio *C.BIO, buf *C.char, num C.int) C.int {
    var conn *Conn = (*BIO)(bio.ptr).conn
    var size int = int(num)
    data := GoSliceFromCString(buf, size)
    n, err := conn.conn.Read(data)
    if err != nil && err != io.EOF {
        //return Error to openssl
        C.ERR_put_error(library_code, 0, 0, C.CString("go-ssl/tls/bio.go"), 51)
        C.go_conn_put_error(C.CString(fmt.Sprintf("%s", err)))
        return C.int(-1)
    }
    return C.int(n)
}
//export go_conn_bio_new
func go_conn_bio_new(bio *C.BIO) C.int {
    //we are initializing here
    bio.init = C.int(1)
    //see mem_new()
    bio.num = C.int(-1)
    bio.ptr = nil
    bio.flags = C.BIO_FLAGS_UPLINK
    return C.int(1)
}
//export go_conn_bio_free
func go_conn_bio_free(bio *C.BIO) C.int {
    return C.int(0)
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
