// Package aes implements AES128 ECB hashing
package aes

/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "openssl/aes.h"
#cgo pkg-config: openssl
*/
import "C"
import (
	"crypto/cipher"
	"errors"
	"strconv"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

const BlockSize = 16

type aesKey struct {
	_aes_encrypt_key C.AES_KEY
	_aes_decrypt_key C.AES_KEY
}

var (
	errorSettingKey   = errors.New("problem setting key")
	errorWrongSizeKey = errors.New("key length not valid")
	errorInvalidKey   = errors.New("initial keys are not valid")
)

//Construct a new instance. see crypto/aes
// returning a block cipher that satisfies the crypto/cipher.Block interface
func NewCipher(key []byte) (cipher.Block, error) {
	aes := new(aesKey)
	key_p := pointerFromBytes(key)
	key_bits := C.int(len(key) * 8)
	if ret := C.AES_set_encrypt_key(key_p, key_bits, &aes._aes_encrypt_key); ret != 0 {
		// in case the error is something deep in OpenSSL land
		if err := sslerr.Error(); err != nil {
			return aes, err
		}
		if ret == -1 {
			return aes, errorInvalidKey
		}
		if ret == -2 {
			return aes, errorWrongSizeKey
		}
		// standard fallback error
		return aes, errorSettingKey
	}
	if ret := C.AES_set_decrypt_key(key_p, key_bits, &aes._aes_decrypt_key); ret != 0 {
		// in case the error is something deep in OpenSSL land
		if err := sslerr.Error(); err != nil {
			return aes, err
		}
		if ret == -1 {
			return aes, errorInvalidKey
		}
		if ret == -2 {
			return aes, errorWrongSizeKey
		}
		// standard fallback error
		return aes, errorSettingKey
	}
	return aes, nil
}

func pointerFromBytes(b []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}
func (self *aesKey) BlockSize() int { return BlockSize }
func (self *aesKey) Encrypt(dst, src []byte) {
	if goCompatible {
		// this something the golang crypto/aes does, that does not happen for OpenSSL.
		if len(src) < BlockSize {
			panic("crypto/aes: input not full block")
		}
		if len(dst) < BlockSize {
			panic("crypto/aes: output not full block")
		}
	}

	dst_p := pointerFromBytes(dst)
	src_p := pointerFromBytes(src)
	C.AES_ecb_encrypt(src_p, dst_p, &self._aes_encrypt_key, C.AES_ENCRYPT)

	// for safe measure
	err := sslerr.Error()
	if err != nil {
		panic(err.Error())
	}
}
func (self *aesKey) Decrypt(dst, src []byte) {
	if goCompatible {
		// this something the golang crypto/aes does, that does not happen for OpenSSL.
		if len(src) < BlockSize {
			panic("crypto/aes: input not full block")
		}
		if len(dst) < BlockSize {
			panic("crypto/aes: output not full block")
		}
	}

	dst_p := pointerFromBytes(dst)
	src_p := pointerFromBytes(src)
	C.AES_ecb_encrypt(src_p, dst_p, &self._aes_decrypt_key, C.AES_DECRYPT)

	// for safe measure
	err := sslerr.Error()
	if err != nil {
		panic(err.Error())
	}
}

// Here for compatibility with 'crypto/aes'
type KeySizeError int

// Here for compatibility with 'crypto/aes'
func (k KeySizeError) Error() string {
	return "crypto/aes: invalid key size " + strconv.Itoa(int(k))
}
