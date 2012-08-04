// package evp provides wrappers around OpenSSL's generic
// evp interfaces for symmetric/asymetric ciphers and digests
package evp
/*
#cgo pkg-config: openssl
#include "openssl/evp.h"
*/
import "C"

type PKey struct {
    pkey *C.EVP_PKEY
}
type Digest struct {
    evp_md *C.EVP_MD
}
func (self *Digest) Type() (int) {
    return int(C.EVP_MD_type(self.evp_md))
}
func (self *Digest) Name() (string) {
    return C.GoString(C.OBJ_nid2sn(C.int(self.Type())))
}
func (self *Digest) Size() (int) {
    return int(C.EVP_MD_size(self.evp_md))
}
func (self *Digest) BlockSize() (int) {
    return int(C.EVP_MD_block_size(self.evp_md))
}

// type DigestCtx struct {
//     evp_md_ctx *C.EVP_MD_CTX
// }

// type CipherInfo struct {
//     evp_cipher_info *C.EVP_CIPHER_INFO
// }
