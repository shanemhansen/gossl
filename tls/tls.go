package tls

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl

*/
import "C"
import "errors"
import "go-ssl/x509"
import "net"

//import "fmt"
import "unsafe"
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
    ctx    *C.SSL_CTX
}

// Wrap a connection using an existing ssl context
func Server(conn net.Conn, config *cryptotls.Config, ctx *C.SSL_CTX) (c *Conn, err error) {
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
    if ssl_err != C.SSL_ERROR_NONE {
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

//create an OpenSSL EVP_PKEY object
func loadPrivateKey(buf []byte) (*C.EVP_PKEY, error) {
    bio := C.BIO_new_mem_buf(unsafe.Pointer(&buf[0]), C.int(len(buf)))
    if bio == nil {
        return nil, errors.New("problem converting der key to openssl key")
    }

    pkey := C.d2i_PrivateKey_bio(bio, nil)

    if pkey == nil {
        return nil, errors.New(sslErrorMessage())
    }
    return pkey, nil
}

//Wrap an existing listener + crypto config and return a new TLS enabled listener.
func NewListener(inner net.Listener, config *cryptotls.Config) (*Listener, error) {
    l := new(Listener)
    l.Listener = inner
    l.config = config
    //FIXME hardcoded in method
    l.ctx = C.SSL_CTX_new(C.SSLv23_method())
    if l.ctx == nil {
        msg := sslErrorMessage()
        return nil, errors.New("problem creating ssl context:\n" + msg)
    }
    //set certificates
    //grab the private key
    Kr := config.Certificates[0].PrivateKey
    private_key_der, err := extractDERKey(Kr)
    private_key, err := loadPrivateKey(private_key_der)
    //set the private key into the context
    if int(C.SSL_CTX_use_PrivateKey(l.ctx, private_key)) != 1 {
        return nil, errors.New("problem loading key " + sslErrorMessage())
    }
    cert, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
    if err != nil {
        return nil, err
    }
    if int(C.SSL_CTX_use_certificate(l.ctx, (*C.X509)(unsafe.Pointer(cert.X509)))) != 1 {
        return nil, errors.New("problem loading cert " + sslErrorMessage())
    }
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
