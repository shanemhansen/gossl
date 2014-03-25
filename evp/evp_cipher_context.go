package evp

/*
#cgo pkg-config: openssl
#include "openssl/evp.h"
*/
import "C"
import "unsafe"
import "runtime"
import "errors"

type CipherCtx struct {
	evp_cipher_ctx *C.EVP_CIPHER_CTX
}

//initialize the cipher
func NewCipherCtx() *CipherCtx {
	ctx := CipherCtx{new(C.EVP_CIPHER_CTX)}
	C.EVP_CIPHER_CTX_init(ctx.evp_cipher_ctx)
	ctx.SetPadding(0)
	runtime.SetFinalizer(&ctx, CleanUpCipherCtx)
	return &ctx
}
func CleanUpCipherCtx(self *CipherCtx) {
	//ignore return value. Do we want to
	//panic in a finalizer?
	C.EVP_CIPHER_CTX_cleanup(self.evp_cipher_ctx)
}
func (self *CipherCtx) EncryptInit(cipher *Cipher, key []byte, iv []byte) error {
	if cipher == nil {
		return errors.New("Cipher is required")
	}
	key_p := (*C.uchar)(unsafe.Pointer(C.CString(string(key))))
	defer C.free(unsafe.Pointer(key_p))
	iv_p := (*C.uchar)(unsafe.Pointer(C.CString(string(iv))))
	defer C.free(unsafe.Pointer(iv_p))
	ret := int(C.EVP_EncryptInit(
		self.evp_cipher_ctx, cipher.evp_cipher, key_p, iv_p))
	if ret == 1 {
		return nil
	}
	return errors.New("failure")
}
func (self *CipherCtx) Encrypt(dst, src []byte) {
	if _, err := self.EncryptUpdate(dst, src); err != nil {
		panic(err)
	}
}
func (self *CipherCtx) Decrypt(dst, src []byte) {
	if _, err := self.DecryptUpdate(dst, src); err != nil {
		panic(err)
	}
}
func (self *CipherCtx) EncryptUpdate(out []byte, in []byte) (int, error) {
	outbuf := (*C.uchar)(unsafe.Pointer(&out[0]))
	var outlen C.int
	inbuf := (*C.uchar)(unsafe.Pointer(&in[0]))
	inlen := len(in)
	ret := C.EVP_EncryptUpdate(self.evp_cipher_ctx, outbuf, &outlen, inbuf, C.int(inlen))
	if int(ret) != 1 {
		return int(outlen), errors.New("problem encrypting")
	}

	return int(outlen), nil
}
func (self *CipherCtx) EncryptFinal(out []byte) (int, error) {
	outbuf := (*C.uchar)(unsafe.Pointer(&out[0]))
	var outlen C.int
	ret := C.EVP_EncryptFinal(self.evp_cipher_ctx, outbuf, &outlen)
	if int(ret) != 1 {
		return int(outlen), errors.New("problem encrypting")
	}
	return int(outlen), nil
}
func (self *CipherCtx) DecryptInit(cipher *Cipher, key []byte, iv []byte) error {
	key_p := (*C.uchar)(unsafe.Pointer(C.CString(string(key))))
	defer C.free(unsafe.Pointer(key_p))
	iv_p := (*C.uchar)(unsafe.Pointer(C.CString(string(iv))))
	defer C.free(unsafe.Pointer(iv_p))

	ret := int(C.EVP_DecryptInit(
		self.evp_cipher_ctx, cipher.evp_cipher, key_p, iv_p))
	if ret == 1 {
		return nil
	}
	return errors.New("failure")
}
func (self *CipherCtx) DecryptUpdate(dst []byte, src []byte) (int, error) {
	dstbuf := (*C.uchar)(unsafe.Pointer(&dst[0]))
	var dstlen C.int
	srcbuf := (*C.uchar)(unsafe.Pointer(&src[0]))
	srclen := len(src)
	ret := C.EVP_DecryptUpdate(self.evp_cipher_ctx, dstbuf, &dstlen, srcbuf, C.int(srclen))
	if int(ret) != 1 {
		return 0, errors.New("problem decrypting")
	}

	return int(dstlen), nil
}
func (self *CipherCtx) DecryptFinal(out []byte) (int, error) {
	outbuf := (*C.uchar)(unsafe.Pointer(&out[0]))
	var outlen C.int
	ret := C.EVP_DecryptFinal(self.evp_cipher_ctx, outbuf, &outlen)
	if int(ret) != 1 {
		return 0, errors.New("problem decrypting")
	}
	return int(outlen), nil
}
func (self *CipherCtx) nid() int {
	return int(C.EVP_CIPHER_CTX_nid(self.evp_cipher_ctx))
}
func (self *CipherCtx) name() string {
	name_p := C.OBJ_nid2sn(C.int(self.nid()))
	return C.GoString(name_p)
}
func (self *CipherCtx) BlockSize() int {
	return int(C.EVP_CIPHER_CTX_block_size(self.evp_cipher_ctx))
}
func (self *CipherCtx) KeyLength() int {
	return int(C.EVP_CIPHER_CTX_key_length(self.evp_cipher_ctx))
}
func (self *CipherCtx) IVLength() int {
	return int(C.EVP_CIPHER_CTX_iv_length(self.evp_cipher_ctx))
}
func (self *CipherCtx) Cipher() *Cipher {
	return newCipher(C.EVP_CIPHER_CTX_cipher(self.evp_cipher_ctx))
}
func (self *CipherCtx) Type() int {
	return int(C.EVP_CIPHER_type(self.Cipher().evp_cipher))
}
func (self *CipherCtx) SetPadding(pad int) int {
	return int(C.EVP_CIPHER_CTX_set_padding(self.evp_cipher_ctx, C.int(pad)))
}
func (self *CipherCtx) Mode() int {
	return int(C.EVP_CIPHER_CTX_flags(self.evp_cipher_ctx) & C.EVP_CIPH_MODE)
}
