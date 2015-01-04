// package evp provides wrappers around OpenSSL's generic
// evp interfaces for symmetric/asymetric ciphers and digests
package evp

/*
#cgo pkg-config: openssl
#include "openssl/evp.h"
#include "openssl/ssl.h"
#include "openssl/bio.h"
*/
import "C"
import (
	"errors"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

//Wrapper around OpenSSL's EVP_PKEY
type PKey struct {
	PKey *C.EVP_PKEY
}

func (self *PKey) DumpPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	defer C.BIO_free(bio)
	if bio == nil {
		return nil, errors.New("problem converting pem key to openssl key")
	}
	ret := C.PEM_write_bio_PrivateKey(bio, self.PKey, nil, nil, 0, nil, nil)
	if int(ret) == 0 {
		return nil, sslerr.Error()
	}
	var temp *C.char
	buf_len := C.BIO_ctrl(bio, C.BIO_CTRL_INFO, C.long(0), unsafe.Pointer(&temp))
	buffer := C.GoBytes(unsafe.Pointer(temp), C.int(buf_len))
	return buffer, nil
}

//Interface to message digest algorithms
type Digest struct {
	evp_md *C.EVP_MD
}

func (self *Digest) Type() int {
	return int(C.EVP_MD_type(self.evp_md))
}
func (self *Digest) Name() string {
	return C.GoString(C.OBJ_nid2sn(C.int(self.Type())))
}
func (self *Digest) Size() int {
	return int(C.EVP_MD_size(self.evp_md))
}
func (self *Digest) BlockSize() int {
	return int(C.EVP_MD_block_size(self.evp_md))
}

//Helper function to load a private key from it's bytes
func LoadPrivateKeyPEM(buf []byte) (*PKey, error) {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if bio == nil {
		return nil, errors.New("problem converting der key to openssl key")
	}

	pkey := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if pkey == nil {
		return nil, errors.New("Problem reading key:" + sslerr.SSLErrorMessage())
	}
	return &PKey{PKey: pkey}, nil
}
func LoadPrivateKeyDER(buf []byte) (*PKey, error) {
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&buf[0]), C.int(len(buf)))
	if bio == nil {
		return nil, errors.New("problem converting der key to openssl key")
	}

	pkey := C.d2i_PrivateKey_bio(bio, nil)
	if pkey == nil {
		return nil, sslerr.Error()
	}
	return &PKey{PKey: pkey}, nil
}
