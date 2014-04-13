package gossl

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
extern int get_errno(void);

*/
import "C"
import "io"
import "unsafe"
import "syscall"
import "github.com/shanemhansen/gossl/sslerr"
import "errors"

type SSL struct {
	SSL *C.SSL
}

func NewSSL(context *Context) *SSL {
	ssl := &SSL{C.SSL_new(context.Ctx)}
	return ssl
}

func (self *SSL) Free() {
	C.SSL_free(self.SSL)
}
func (self *SSL) SetBIO(readbio *BIO, writebio *BIO) {
	C.SSL_set_bio(self.SSL,
		(*C.BIO)(unsafe.Pointer(readbio.BIO)),
		(*C.BIO)(unsafe.Pointer(writebio.BIO)))
}
func (self *SSL) SetAcceptState() {
	C.SSL_set_accept_state(self.SSL)
}
func (self *SSL) SetConnectState() {
	C.SSL_set_connect_state(self.SSL)
}

func (self *SSL) Shutdown() error {
	//shutdown should happen in 2 steps
	//see http://www.openssl.org/docs/ssl/SSL_shutdown.html
	defer self.Free()
	ret := C.SSL_shutdown(self.SSL)
	if int(ret) == 0 {
		ret = C.SSL_shutdown(self.SSL)
		if int(ret) != 1 {
			return self.getError(ret)
		}

	}
	return nil

}
func (self *SSL) Handshake() error {
	ret := C.SSL_do_handshake(self.SSL)
	return self.getError(ret)
}
func (self *SSL) Read(b []byte) (int, error) {
	length := len(b)
	ret := C.SSL_read(self.SSL, unsafe.Pointer(&b[0]), C.int(length))
	if err := self.getError(ret); err != nil {
		return 0, err
	}

	return int(ret), nil
}
func (self *SSL) Write(b []byte) (int, error) {
	length := len(b)
	ret := C.SSL_write(self.SSL, unsafe.Pointer(&b[0]), C.int(length))
	if err := self.getError(ret); err != nil {
		return 0, err
	}

	return int(ret), nil
}
func (self *SSL) getError(ret C.int) error {
	err := C.SSL_get_error(self.SSL, ret)
	switch err {
	case C.SSL_ERROR_NONE:
		return nil
	case C.SSL_ERROR_ZERO_RETURN:
		return io.EOF
	case C.SSL_ERROR_SYSCALL:
		if int(C.ERR_peek_error()) != 0 {
			return syscall.Errno(C.get_errno())
		}

	default:
		msg := sslerr.SSLErrorMessage()
		return errors.New(msg)
	}
	return nil
}
