package evp

/*
#cgo pkg-config: openssl
#include "openssl/evp.h"

// workaround their macros
void my_add_add_algorithms(void) {
	OpenSSL_add_all_algorithms();
}
*/
import "C"
import "unsafe"

func init() {
	//OpenSSLAddAllCiphers()
	//OpenSSLAddAllDigests()
	OpenSSLAddAllAlgorithms()
}

type Cipher struct {
	evp_cipher *C.EVP_CIPHER
}

func newCipher(cipher *C.EVP_CIPHER) *Cipher {
	if cipher == nil {
		return nil
	}
	return &Cipher{cipher}
}
func (cipher *Cipher) Nid() int {
	return int(C.EVP_CIPHER_nid(cipher.evp_cipher))
}
func (cipher *Cipher) BlockSize() int {
	return int(C.EVP_CIPHER_block_size(cipher.evp_cipher))
}
func (cipher *Cipher) KeyLength() int {
	return int(C.EVP_CIPHER_key_length(cipher.evp_cipher))
}
func (cipher *Cipher) IVLength() int {
	return int(C.EVP_CIPHER_iv_length(cipher.evp_cipher))
}
func CipherByName(name string) *Cipher {
	name_p := C.CString(name)
	defer C.free(unsafe.Pointer(name_p))
	return newCipher(C.EVP_get_cipherbyname(name_p))
}

func CipherByNid(nid int) *Cipher {
	return newCipher(C.EVP_get_cipherbyname(C.OBJ_nid2sn(C.int(nid))))
}

func OpenSSLAddAllCiphers() {
	C.OpenSSL_add_all_ciphers()
}
func OpenSSLAddAllDigests() {
	C.OpenSSL_add_all_digests()
}
func OpenSSLAddAllAlgorithms() {
	C.my_add_add_algorithms()
}
