package tls
/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl

void clear_sys_error(void) {
 errno = 0;
}
*/
import "C"

import "time"
import "net"
import "errors"
import "unsafe"
//import "fmt"

import cryptotls "crypto/tls"

type Conn struct {
    conn net.Conn
    config *cryptotls.Config
    ssl *C.SSL
    ctx *C.SSL_CTX
    //TODO add support for fd.
    //this is done over a BIO
    //which allows you to layer things
    bio *BIO
    err error

}
func NewConn(self *Conn) (*Conn, error) {
    if self == nil {
        self = new(Conn)
    }
    self.bio = New(self)
    self.ssl = C.SSL_new(self.ctx)
    C.SSL_set_bio(self.ssl, self.bio.c_bio, self.bio.c_bio)
    C.SSL_set_accept_state(self.ssl)
    return self, nil
}
func (self *Conn) Close() error {
    //free's underlying bios.
    defer C.SSL_free(self.ssl)
    defer self.conn.Close()

    //shutdown should happen in 2 steps
    //see http://www.openssl.org/docs/ssl/SSL_shutdown.html
    ret := C.SSL_shutdown(self.ssl)
    if int(ret) == 0 {
        ret = C.SSL_shutdown(self.ssl)
        if int(ret) != 1 {
            err := C.SSL_get_error(self.ssl, ret);
            if err != C.SSL_ERROR_NONE {
                return errors.New(sslErrorMessage())
            }
        }
        
    }
    return nil
}
func (self *Conn) LocalAddr() net.Addr {
    return self.conn.LocalAddr()
}
func (self *Conn) RemoteAddr() net.Addr {
    return self.conn.RemoteAddr()
}
func (self *Conn) Read(b []byte) (int, error) {
    length := len(b)
    ret := C.SSL_read(self.ssl, unsafe.Pointer(&b[0]), C.int(length))
    err := C.SSL_get_error(self.ssl, ret);
    if err != C.SSL_ERROR_NONE {
        return 0, errors.New("error reading " + sslErrorMessage())
    }
    return length, nil
}
func (self *Conn) Write(b []byte) (int, error) {
    length := len(b)
    ret := C.SSL_write(self.ssl, unsafe.Pointer(&b[0]), C.int(length))
    err := C.SSL_get_error(self.ssl, ret);
    if err != C.SSL_ERROR_NONE {
        return 0, errors.New("error writing " + sslErrorMessage())
    }
    return length, nil
}
func (self *Conn) SetDeadline(t time.Time) error {
    return nil
}
func (self *Conn) SetReadDeadline(t time.Time) error {
    return nil
}
func (self *Conn) SetWriteDeadline(t time.Time) error {
    return nil
}

func (self *Conn) bio_read(b []byte) (int, error) {
    C.clear_sys_error()
    ret := C.BIO_read(self.bio.c_bio, unsafe.Pointer(&b[0]), C.int(len(b)))
    err := C.SSL_get_error(self.ssl, ret);
    if err < 0 {
        return 0, errors.New(sslErrorMessage())
    }
    return int(ret), nil
}
func (self *Conn) bio_write(b []byte) (int, error) {
    C.clear_sys_error()
    ret := C.BIO_write(self.bio.c_bio, unsafe.Pointer(&b[0]), C.int(len(b)))
    err := C.SSL_get_error(self.ssl, ret);
    if err < 0 {
        return 0, errors.New(sslErrorMessage())
    }
    return int(ret), nil
}

func (self *Conn) Handshake() C.int {
    ret := C.SSL_do_handshake(self.ssl)
    err := C.SSL_get_error(self.ssl, ret);
    return err
}

func sslErrorMessage() string {
    msg := ""
    var err_code C.ulong
    var flags C.int
    var data *C.char
    for {
        
        err_code = C.ERR_get_error_line_data(nil, nil, &data, &flags)
        if err_code == 0 {
            break
        }
        msg += C.GoString(C.ERR_lib_error_string(err_code))+"\n"   
        msg += C.GoString(C.ERR_func_error_string(err_code))+"\n"   
        msg += C.GoString(C.ERR_reason_error_string(err_code))+"\n"
        if flags&C.ERR_TXT_STRING != 0{
            msg += C.GoString(data)+"\n"
        }
        if flags&C.ERR_TXT_MALLOCED != 0{
            C.CRYPTO_free(unsafe.Pointer(data))
        } else {
            //regular free.
            C.free(unsafe.Pointer(data))
        }
    }
    return msg
}
