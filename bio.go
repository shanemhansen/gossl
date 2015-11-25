package gossl

/*
#cgo pkg-config: openssl
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

extern int go_conn_bio_write(BIO* bio, char* buf, int num);
extern int go_conn_bio_read(BIO* bio, char* buf, int num);
extern int go_conn_bio_new(BIO* bio);
extern int go_conn_bio_free(BIO* bio);
extern long go_conn_bio_ctrl(BIO *b, int cmd, long num, void *ptr);

static BIO_METHOD methods_connp = {
	BIO_TYPE_SOURCE_SINK,
	"go net.Conn",
	(int (*)(BIO *, const char *, int))go_conn_bio_write,
	go_conn_bio_read,
	NULL,
	NULL,
	go_conn_bio_ctrl,
	go_conn_bio_new,
	go_conn_bio_free
};

static BIO_METHOD* BIO_s_conn()
{
	return &methods_connp;
}

static void clear_sys_error(void)
{
	errno = 0;
}

static void set_errno(int e)
{
	errno = e;
}
*/
import "C"
import (
	"io"
	"net"
	"reflect"
	"syscall"
	"unsafe"
)

type BIO struct {
	BIO  *C.BIO
	conn *Conn
}

func NewBIO(method *BIOMethod) *BIO {
	return &BIO{BIO: C.BIO_new(method.BIOMethod)}
}

//Thin wrappers over OpenSSL bio.
//See BIO_read documentation for return value negative means error
//error message is gotten be calling ssl.getError()
func (bio *BIO) Read(b []byte) int {
	C.clear_sys_error()
	return int(C.BIO_read(bio.BIO, unsafe.Pointer(&b[0]), C.int(len(b))))
}

//See BIO_write
func (bio *BIO) Write(b []byte) int {
	C.clear_sys_error()
	return int(C.BIO_write(bio.BIO, unsafe.Pointer(&b[0]), C.int(len(b))))
}

func (bio *BIO) SetAppData(conn *Conn) {
	bio.BIO.ptr = unsafe.Pointer(conn)
}

func (bio *BIO) GetAppData() *Conn {
	return (*Conn)(bio.BIO.ptr)
}

func (bio *BIO) Ctrl(cmd int, larg int, data unsafe.Pointer) int {
	return int(C.BIO_ctrl(bio.BIO, C.int(cmd), C.long(larg), data))
}

func (bio *BIO) GetBytes() []byte {
	var temp *C.char
	buf_len := bio.Ctrl(int(C.BIO_CTRL_INFO), 0, unsafe.Pointer(&temp))
	return C.GoBytes(unsafe.Pointer(temp), C.int(buf_len))
}

type BIOMethod struct {
	BIOMethod *C.BIO_METHOD
}

func newBIOMethod(method *C.BIO_METHOD) *BIOMethod {
	return &BIOMethod{method}
}

func BIOConn() *BIOMethod {
	return newBIOMethod(C.BIO_s_conn())
}

func BIOSMem() *BIOMethod {
	return newBIOMethod(C.BIO_s_mem())
}

//export go_conn_bio_write
func go_conn_bio_write(bio *C.BIO, buf *C.char, num C.int) C.int {
	conn := (*Conn)(bio.ptr)
	data := goSliceFromCString(buf, int(num))
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
	conn := (*Conn)(bio.ptr)
	data := goSliceFromCString(buf, int(num))
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
func goSliceFromCString(cArray *C.char, size int) (cslice []byte) {
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
