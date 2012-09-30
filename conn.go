package gossl

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl
*/
import "C"

import "time"
import "net"
import "fmt"

import cryptotls "crypto/tls"

var _ = fmt.Println

type Conn struct {
    conn   net.Conn
    config *cryptotls.Config
    ssl    *SSL
    bio    *BIO
    err    error
}

func (self *Conn) Conn() net.Conn {
    return self.conn
}
func NewConn(ctx *Context, cfg *cryptotls.Config, conn net.Conn) (*Conn, error) {
    self := &Conn{ssl: NewSSL(ctx),
        bio:    NewBIO(BIOConn()),
        config: cfg,
        conn:   conn}
    self.bio.SetAppData(self)
    self.ssl.SetBIO(self.bio, self.bio)
    self.ssl.SetAcceptState()
    return self, nil
}
func (self *Conn) Close() error {
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
