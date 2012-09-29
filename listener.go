package gossl

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl

*/
import "C"
import "errors"
import "github.com/shanemhansen/gossl/evp"

import "net"

//import "fmt"
import cryptotls "crypto/tls"
import cryptorsa "crypto/rsa"
import cryptox509 "crypto/x509"

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
    config *cryptotls.Config
    ctx    *Context
}

// Wrap a connection using an existing ssl context
func Server(conn net.Conn, config *cryptotls.Config, ctx *Context) (c *Conn, err error) {
    c, err = NewConn(&Conn{conn: conn, config: config, ctx: ctx})
    return
}

// Accept a new connection and complete handshake.
// TODO: do handshake later, this blocks future accepts.
func (self *Listener) Accept() (net.Conn, error) {
    c, err := self.Listener.Accept()
    if err != nil {
        return nil, err
    }
    myconnection, err := Server(c, self.config, self.ctx)
    //ssl_err := myconnection.Handshake()
    ssl_err := myconnection.Handshake()
    if ssl_err != nil {
        return nil, errors.New("Handshake problem" + sslErrorMessage())
    }
    return myconnection, nil
}

//helper function to get the der bytes from a Kr object.
func extractDERKey(Kr interface{}) ([]byte, error) {
    var key *cryptorsa.PrivateKey
    var ok bool
    //cast to rsa
    if key, ok = Kr.(*cryptorsa.PrivateKey); !ok {
        return nil, errors.New("crypto/tls: found non-RSA private key")
    }
    //get the raw bytes
    private_key_der := cryptox509.MarshalPKCS1PrivateKey(key)
    return private_key_der, nil

}

//More OpenSSL'ish interface to create a listener
func NewListenerFromContext(inner net.Listener) {
}

//Wrap an existing listener + crypto config and return a new TLS enabled listener.
func NewListener(inner net.Listener, config *cryptotls.Config) (*Listener, error) {
    l := new(Listener)
    l.Listener = inner
    l.config = config
    //FIXME hardcoded in method
    l.ctx = NewContext(SSLv23Method())
    if l.ctx == nil {
        msg := sslErrorMessage()
        return nil, errors.New("problem creating ssl context:\n" + msg)
    }
    //set certificates
    //grab the private key
    Kr := config.Certificates[0].PrivateKey
    private_key_der, err := extractDERKey(Kr)
    private_key, err := evp.LoadPrivateKeyDER(private_key_der)
    if err != nil {
        return nil, err
    }
    //set the private key into the context
    err = l.ctx.UsePrivateKey(private_key)
    if err != nil {
        return nil, errors.New("problem loading key " + sslErrorMessage())
    }
    cert, err := ParseCertificate(config.Certificates[0].Certificate[0])
    if err != nil {
        return nil, err
    }
    err = l.ctx.UseCertificate(cert)
    if err != nil {
        return nil, errors.New("problem loading key " + sslErrorMessage())
    }
    //    if int(C.SSL_CTX_use_certificate(l.ctx.Ctx, (*C.X509)(unsafe.Pointer(cert.X509)))) != 1 {
    //        return nil, errors.New("problem loading cert " + sslErrorMessage())
    //    }
    return l, nil
}

//Listen on network, laddr and return a listener that will handle TLS connections.
func Listen(network, laddr string, config *cryptotls.Config) (*Listener, error) {
    if config == nil || len(config.Certificates) == 0 {
        return nil, errors.New("tls.Listen: no certificates in configuration")
    }
    listener, err := net.Listen(network, laddr)
    if err != nil {
        return nil, err
    }
    return NewListener(listener, config)
}
