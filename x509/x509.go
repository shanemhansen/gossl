// Package x509 provides methods for coverting between OpenSSL x509
// certificates and DER format. The crypto/x509 package has a much more beautiful
// interface when compared to OpenSSL imo.
// These methods will basically be helpful in the tls/ssl packages for
// passing in certificate objects to the context.
package x509
/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/x509.h"
#include "openssl/bio.h"
#cgo pkg-config: openssl


*/
import "C"
import "unsafe"
import "errors"
import "encoding/pem"

//A wrapper around OpenSSL's X509
type Certificate struct {
    X509 *C.X509
}

//Export an OpenSSL X509 to a DER buffer
func (self *Certificate) DumpDERCertificate() ([]byte, error) {
    bio := C.BIO_new(C.BIO_s_mem())
    defer C.BIO_free(bio)
    ret := C.i2d_X509_bio(bio, self.X509)
    if ret == 0 {
        return nil, errors.New("problem dumping certificate")
    }
    var temp *C.char
    buf_len :=  C.BIO_ctrl(bio,  C.BIO_CTRL_INFO, 0, unsafe.Pointer(&temp))
    return C.GoBytes(unsafe.Pointer(temp), C.int(buf_len)), nil
}

//Helper function that calls encoding/pem to convert DER to PEM
func ParseCertificatePEM(pemData []byte) (*Certificate, error) {
    asn1Block, _ := pem.Decode(pemData)
    return ParseCertificate(asn1Block.Bytes)
}

//Import an OpenSSL X509 certificate from a DER buffer
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
    //with credit to exarkun and pyopenssl's crypto.c
    //you're my inspiration!
    length := C.int(len(asn1Data))
    buffer := unsafe.Pointer(&asn1Data[0])
    bio := C.BIO_new_mem_buf(buffer, length)
    sslCert := C.d2i_X509_bio(bio, nil)
    if sslCert == nil {
        return nil, errors.New("problem loading cert")
    }
    cert := new(Certificate)
    cert.X509 = sslCert
    return cert, nil
}
