package evp
/*
#cgo pkg-config: openssl
#include "openssl/evp.h"
*/
import "C"
import "unsafe"

var Init int = func() int {
    C.OpenSSL_add_all_ciphers()
    return 1
}()

type Cipher struct {
    evp_cipher *C.EVP_CIPHER
}

func newCipher(self *C.EVP_CIPHER) (*Cipher) {
    if self == nil {
        return nil
    }
    return &Cipher{self}
}
func (self *Cipher) Nid() int {
    return int(C.EVP_CIPHER_nid(self.evp_cipher))
}
func (self *Cipher) BlockSize() int {
    return int(C.EVP_CIPHER_block_size(self.evp_cipher))
}
func (self *Cipher) KeyLength() int {
    return int(C.EVP_CIPHER_key_length(self.evp_cipher))
}
func (self *Cipher) IVLength() int {
    return int(C.EVP_CIPHER_iv_length(self.evp_cipher))
}
func CipherByName(name string) (*Cipher) {
    name_p := C.CString(name)
    defer C.free(unsafe.Pointer(name_p))
    return newCipher(C.EVP_get_cipherbyname(name_p))
}
func CipherByNid(nid int) (*Cipher) {
    return newCipher(C.EVP_get_cipherbyname(C.OBJ_nid2sn(C.int(nid))))
}
func OpenSSLAddAllCiphers() {
    C.OpenSSL_add_all_ciphers()
}
