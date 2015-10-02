package net

/*
#cgo pkg-config: openssl
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
*/
import "C"
import (
	"crypto/tls"
	"errors"
	"net"
	"time"
)

func Dial(network, address string, config *tls.config) (*Conn, error) {
	switch network {
	case "tcp":
	default:
		errors.New("unsupported network")
	}
	netConn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	switch network {
	case "tcp":
		ctx := C.SSL_CTX_new(C.TLSv1_2_client_method())
		if ctx == nil {
			return nil, errors.New("problem creating ssl context")
		}
		ssl := C.SSL_new(ctx)
		if ssl == nil {
			return nil, errors.New("problem creating ssl")
		}

		break
	//case "udp":
	//context := C.SSL_CTX_new(C.DTLSv1_client_method())
	//break
	default:
		return nil, errors.New("unsupported network")
	}

}

type Conn struct {
	bio  *C.BIO
	ctx  *C.SSL_CTX
	ssl  *C.SSL
	conn net.Conn
}

func (c *Conn) Read(b []byte) (n int, err error) {

}

func (c *Conn) Write(b []byte) (n int, err error) {

}

func (c *Conn) Close() error {

}

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {

}

func (c *Conn) SetReadDeadline(t time.Time) error {

}

func (c *Conn) SetWriteDeadline(t time.Time) error {

}
