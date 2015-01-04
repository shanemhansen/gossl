package evp

/*
#cgo pkg-config: openssl
#include "openssl/evp.h"
*/
import "C"
import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

type CipherCtx struct {
	evp_cipher_ctx *C.EVP_CIPHER_CTX
}

// NewCipherCtx initializes a new cipher
func NewCipherCtx() *CipherCtx {
	ctx := CipherCtx{new(C.EVP_CIPHER_CTX)}
	C.EVP_CIPHER_CTX_init(ctx.evp_cipher_ctx)
	ctx.SetPadding(0)
	runtime.SetFinalizer(&ctx, CleanUpCipherCtx)
	return &ctx
}
func CleanUpCipherCtx(ctx *CipherCtx) {
	//ignore return value. Do we want to
	//panic in a finalizer?
	C.EVP_CIPHER_CTX_cleanup(ctx.evp_cipher_ctx)
}

var (
	ErrCipherRequired    = errors.New("Cipher is required")
	ErrProblemEncrypting = errors.New("problem encrypting")
	ErrProblemDecrypting = errors.New("problem decrypting")
	ErrFailure           = errors.New("failure")
)

func (ctx *CipherCtx) EncryptInit(cipher *Cipher, key []byte, iv []byte) error {
	if cipher == nil {
		return ErrCipherRequired
	}
	key_p := (*C.uchar)(unsafe.Pointer(C.CString(string(key))))
	defer C.free(unsafe.Pointer(key_p))
	iv_p := (*C.uchar)(unsafe.Pointer(C.CString(string(iv))))
	defer C.free(unsafe.Pointer(iv_p))
	ret := int(C.EVP_EncryptInit(
		ctx.evp_cipher_ctx, cipher.evp_cipher, key_p, iv_p))
	if ret != 1 {
		// try to return the openssl error first, if present
		if err := sslerr.Error(); err != nil {
			return err
		} else {
			return ErrFailure
		}
	}
	return nil
}

func (ctx *CipherCtx) Encrypt(dst, src []byte) error {
	_, err := ctx.EncryptUpdate(dst, src)
	return err
}

func (ctx *CipherCtx) Decrypt(dst, src []byte) error {
	_, err := ctx.DecryptUpdate(dst, src)
	return err
}

func (ctx *CipherCtx) EncryptUpdate(out []byte, in []byte) (int, error) {
	outbuf := (*C.uchar)(unsafe.Pointer(&out[0]))
	var outlen C.int
	inbuf := (*C.uchar)(unsafe.Pointer(&in[0]))
	inlen := len(in)
	ret := C.EVP_EncryptUpdate(ctx.evp_cipher_ctx, outbuf, &outlen, inbuf, C.int(inlen))
	if int(ret) != 1 {
		return int(outlen), ErrProblemEncrypting
	}

	return int(outlen), nil
}
func (ctx *CipherCtx) EncryptFinal(out []byte) (int, error) {
	outbuf := (*C.uchar)(unsafe.Pointer(&out[0]))
	var outlen C.int
	ret := C.EVP_EncryptFinal(ctx.evp_cipher_ctx, outbuf, &outlen)
	if int(ret) != 1 {
		return int(outlen), ErrProblemEncrypting
	}
	return int(outlen), nil
}
func (ctx *CipherCtx) DecryptInit(cipher *Cipher, key []byte, iv []byte) error {
	key_p := (*C.uchar)(unsafe.Pointer(C.CString(string(key))))
	defer C.free(unsafe.Pointer(key_p))
	iv_p := (*C.uchar)(unsafe.Pointer(C.CString(string(iv))))
	defer C.free(unsafe.Pointer(iv_p))

	ret := int(C.EVP_DecryptInit(
		ctx.evp_cipher_ctx, cipher.evp_cipher, key_p, iv_p))
	if ret == 1 {
		return nil
	}
	return ErrFailure
}
func (ctx *CipherCtx) DecryptUpdate(dst []byte, src []byte) (int, error) {
	dstbuf := (*C.uchar)(unsafe.Pointer(&dst[0]))
	var dstlen C.int
	srcbuf := (*C.uchar)(unsafe.Pointer(&src[0]))
	srclen := len(src)
	ret := C.EVP_DecryptUpdate(ctx.evp_cipher_ctx, dstbuf, &dstlen, srcbuf, C.int(srclen))
	if int(ret) != 1 {
		return 0, ErrProblemDecrypting
	}

	return int(dstlen), nil
}
func (ctx *CipherCtx) DecryptFinal(out []byte) (int, error) {
	outbuf := (*C.uchar)(unsafe.Pointer(&out[0]))
	var outlen C.int
	ret := C.EVP_DecryptFinal(ctx.evp_cipher_ctx, outbuf, &outlen)
	if int(ret) != 1 {
		return 0, ErrProblemDecrypting
	}
	return int(outlen), nil
}
func (ctx *CipherCtx) nid() int {
	return int(C.EVP_CIPHER_CTX_nid(ctx.evp_cipher_ctx))
}
func (ctx *CipherCtx) name() string {
	name_p := C.OBJ_nid2sn(C.int(ctx.nid()))
	return C.GoString(name_p)
}
func (ctx *CipherCtx) BlockSize() int {
	return int(C.EVP_CIPHER_CTX_block_size(ctx.evp_cipher_ctx))
}
func (ctx *CipherCtx) KeyLength() int {
	return int(C.EVP_CIPHER_CTX_key_length(ctx.evp_cipher_ctx))
}
func (ctx *CipherCtx) IVLength() int {
	return int(C.EVP_CIPHER_CTX_iv_length(ctx.evp_cipher_ctx))
}
func (ctx *CipherCtx) Cipher() *Cipher {
	return newCipher(C.EVP_CIPHER_CTX_cipher(ctx.evp_cipher_ctx))
}
func (ctx *CipherCtx) Type() int {
	return int(C.EVP_CIPHER_type(ctx.Cipher().evp_cipher))
}
func (ctx *CipherCtx) SetPadding(pad int) int {
	return int(C.EVP_CIPHER_CTX_set_padding(ctx.evp_cipher_ctx, C.int(pad)))
}
func (ctx *CipherCtx) Mode() int {
	return int(C.EVP_CIPHER_CTX_flags(ctx.evp_cipher_ctx) & C.EVP_CIPH_MODE)
}
