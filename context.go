package gossl

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
*/
import "C"
import "unsafe"
import "github.com/shanemhansen/gossl/evp"
import sslerr "github.com/shanemhansen/gossl/err"
import "runtime"
import "errors"

type SSL struct {
    SSL *C.SSL
}

func NewSSL(context *Context) *SSL {
    ssl := &SSL{C.SSL_new(context.Ctx)}
    runtime.SetFinalizer(ssl, sslFree)
    return ssl
}

func sslFree(self *SSL) {
    C.SSL_free(self.SSL)
}
func (self *SSL) SetBIO(readbio *BIO, writebio *BIO) {
    C.SSL_set_bio(self.SSL,
        (*C.BIO)(unsafe.Pointer(readbio.BIO)),
        (*C.BIO)(unsafe.Pointer(writebio.BIO)))
    C.SSL_set_accept_state(self.SSL)
}
func (self *SSL) SetAcceptState() {
    C.SSL_set_accept_state(self.SSL)
}
func (self *SSL) Shutdown() error {
    //shutdown should happen in 2 steps
    //see http://www.openssl.org/docs/ssl/SSL_shutdown.html
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
    return length, self.getError(ret)
}
func (self *SSL) Write(b []byte) (int, error) {
    length := len(b)
    ret := C.SSL_write(self.SSL, unsafe.Pointer(&b[0]), C.int(length))
    return length, self.getError(ret)
}

func (self *SSL) getError(ret C.int) error {
    err := C.SSL_get_error(self.SSL, ret)
    if err != C.SSL_ERROR_NONE {
        return errors.New(sslErrorMessage())
    }
    return nil
}

type Context struct {
    Ctx *C.SSL_CTX
}

func NewContext(method *METHOD) *Context {
    return &Context{C.SSL_CTX_new(method.method)}
}

func (self *Context) UsePrivateKey(key *evp.PKey) error {
    if int(C.SSL_CTX_use_PrivateKey(self.Ctx, (*C.EVP_PKEY)(unsafe.Pointer(key.PKey)))) != 1 {
        return errors.New("problem loading key " + sslerr.SSLErrorMessage())
    }
    return nil
}

func (self *Context) UseCertificate(cert *Certificate) error {

    if int(C.SSL_CTX_use_certificate(self.Ctx, (*C.X509)(unsafe.Pointer(cert.X509)))) != 1 {
        return errors.New("problem loading cert " + sslerr.SSLErrorMessage())
    }
    return nil
}
