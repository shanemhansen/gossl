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

var _ = fmt.Println

type Conn struct {
	conn               net.Conn
	ssl                *SSL
	bio                *BIO
	err                error
	handshakeCompleted bool
}

func (self *Conn) Conn() net.Conn {
	return self.conn
}

// basic connection, must call either NewServerConn or NewClientConn
func newConn(ctx *Context, conn net.Conn) (*Conn, error) {
	self := &Conn{ssl: NewSSL(ctx),
		bio:  NewBIO(BIOConn()),
		conn: conn}
	self.bio.SetAppData(self)
	self.ssl.SetBIO(self.bio, self.bio)
	return self, nil
}

// create a new server connection
func NewServerConn(ctx *Context, conn net.Conn) (*Conn, error) {
	sslConn, err := newConn(ctx, conn)
	if err != nil {
		return nil, err
	}

	sslConn.ssl.SetAcceptState()
	return sslConn, nil
}

// create a new client connection
func NewClientConn(ctx *Context, conn net.Conn) (*Conn, error) {
	sslConn, err := newConn(ctx, conn)
	if err != nil {
		return nil, err
	}

	sslConn.ssl.SetConnectState()
	return sslConn, nil
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
	if err := self.Handshake(); err != nil {
		fmt.Printf("handshake failed %r;\n", err)
		return 0, err
	}
	return self.ssl.Read(b)
}
func (self *Conn) Write(b []byte) (int, error) {
	if err := self.Handshake(); err != nil {
		return 0, err
	}
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
func (self *Conn) Handshake() (err error) {
	if !self.handshakeCompleted {
		err = self.ssl.Handshake()
		self.handshakeCompleted = true
	}
	return
}
