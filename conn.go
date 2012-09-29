package gossl

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl
*/
import "C"

import "time"
import "net"

import cryptotls "crypto/tls"

type Conn struct {
    conn   net.Conn
    config *cryptotls.Config
    ssl    *SSL
    ctx    *Context
    //TODO add support for fd.
    //this is done over a BIO
    //which allows you to layer things
    bio *BIO
    err error
}

func (self *Conn) Conn() net.Conn {
    return self.conn
}
func NewConn(self *Conn) (*Conn, error) {
    if self == nil {
        self = new(Conn)
    }
    self.ssl = NewSSL(self.ctx)
    self.bio = NewBIO(BIOConn())
    self.bio.SetAppData(self)
    self.ssl.SetBIO(self.bio, self.bio)
    self.ssl.SetAcceptState()
    return self, nil
}
func (self *Conn) Close() error {
    //free's underlying bios.
    defer self.conn.Close()
    return self.ssl.Shutdown()
}
func (self *Conn) LocalAddr() net.Addr {
    return self.conn.LocalAddr()
}
func (self *Conn) RemoteAddr() net.Addr {
    return self.conn.RemoteAddr()
}
func (self *Conn) Read(b []byte) (int, error) {
    return self.ssl.Read(b)
}
func (self *Conn) Write(b []byte) (int, error) {
    return self.ssl.Write(b)
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
func (self *Conn) Handshake() error {
    return self.ssl.Handshake()
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
        msg += C.GoString(C.ERR_lib_error_string(err_code)) + "\n"
        msg += C.GoString(C.ERR_func_error_string(err_code)) + "\n"
        msg += C.GoString(C.ERR_reason_error_string(err_code)) + "\n"
        if flags&C.ERR_TXT_STRING != 0 {
            msg += C.GoString(data) + "\n"
        }
        if flags&C.ERR_TXT_MALLOCED != 0 {
            //            C.CRYPTO_free(unsafe.Pointer(data))
        } else {
            //regular free.
            //            C.free(unsafe.Pointer(data))
        }
    }
    return msg
}
