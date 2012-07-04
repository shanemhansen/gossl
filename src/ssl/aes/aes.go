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
import "unsafe"
import "errors"
import "crypto/cipher"

const BlockSize = 16

type AESKey struct {
    _aes_encrypt_key C.AES_KEY
    _aes_decrypt_key C.AES_KEY
}

//Construct a new instance. see crypto/aes
func NewCipher(key []byte) (cipher.Block, error) {
    aes := new(AESKey)
    key_p := pointerFromBytes(key)
    key_bits := C.int(len(key)*8)    
    if C.AES_set_encrypt_key(key_p, key_bits, &aes._aes_encrypt_key) != 0 {
        return aes, errors.New("problem setting key")
    }
    if C.AES_set_decrypt_key(key_p, key_bits, &aes._aes_decrypt_key) != 0 {
        return aes, errors.New("problem setting key")
    }
    return aes, nil
}
func pointerFromBytes(b []byte) (*C.uchar) {
    return (*C.uchar)(unsafe.Pointer(&b[0]))
}
func (self *AESKey) BlockSize() int { return BlockSize }
func (self *AESKey) Encrypt(dst, src []byte) {
    dst_p := pointerFromBytes(dst)
    src_p := pointerFromBytes(src)
    C.AES_ecb_encrypt(src_p, dst_p, &self._aes_encrypt_key, C.AES_ENCRYPT)    
}
func (self *AESKey) Decrypt(dst, src []byte) {
    dst_p := pointerFromBytes(dst)
    src_p := pointerFromBytes(src)
    C.AES_ecb_encrypt(src_p, dst_p, &self._aes_decrypt_key, C.AES_DECRYPT)
}
