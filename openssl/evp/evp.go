// package evp provides wrappers around OpenSSL's generic
// evp interfaces for symmetric/asymetric ciphers and digests
package evp

/*
#cgo pkg-config: openssl
#include "openssl/evp.h"
#include "openssl/ssl.h"
*/
import "C"
import "unsafe"
import "errors"
import "github.com/shanemhansen/go-ssl/openssl/err"

type PKey struct {
    PKey *C.EVP_PKEY
}
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
func LoadPrivateKeyPEM(buf []byte) (*PKey, error) {
    bio := C.BIO_new_mem_buf(unsafe.Pointer(&buf[0]), C.int(len(buf)))
    if bio == nil {
        return nil, errors.New("problem converting der key to openssl key")
    }

    pkey := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
    if pkey == nil {
        return nil, errors.New(err.SSLErrorMessage())
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
        return nil, errors.New(err.SSLErrorMessage())
    }
    return &PKey{PKey: pkey}, nil
}

// type DigestCtx struct {
//     evp_md_ctx *C.EVP_MD_CTX
// }

// type CipherInfo struct {
//     evp_cipher_info *C.EVP_CIPHER_INFO
// }
