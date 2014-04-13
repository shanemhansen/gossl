package gossl

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl

*/
import "C"
import "net"

var sslInitialized = Init()

// Initialize the OpenSSL library. Takes care of several bookkeeping functions
// like populating error messages and cipher lists.
func Init() int {
	C.SSL_library_init()
	C.ERR_load_BIO_strings()
	C.SSL_load_error_strings()
	return 0
}

// Listener is a net listener with a TLS context
type Listener struct {
	net.Listener
	Context *Context
}

// Accept a new connection and complete handshake.
// TODO: do handshake later, this blocks future accepts.
func (self *Listener) Accept() (net.Conn, error) {
	c, err := self.Listener.Accept()
	if err != nil {
		return nil, err
	}
	myconnection, err := NewServerConn(self.Context, c)
	//ssl_err := myconnection.Handshake()
	return myconnection, nil
}

//More OpenSSL'ish interface to create a listener
func NewListener(inner net.Listener, context *Context) (*Listener, error) {
	return &Listener{Listener: inner, Context: context}, nil
}
