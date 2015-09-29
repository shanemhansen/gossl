// Package engines provides an interface to the OpenSSL engines api.
// Mostly useful for enabling disabling hardware acceleration afaik.
// See http://www.openssl.org/docs/crypto/engine.html
package engines

/*
#cgo pkg-config: openssl
#include "openssl/engine.h"
*/
import "C"
import (
	"runtime"
	"unsafe"
)

var Init int = func() int {
	C.ERR_load_ENGINE_strings()
	return 1
}()

func LoadBuiltinEngines() {
	C.ENGINE_load_builtin_engines()
}

func LoadCryptodev() {
	C.ENGINE_load_cryptodev()
}

func LoadRdrand() {
	C.ENGINE_load_rdrand()
}

func LoadOpenssl() {
	C.ENGINE_load_openssl()
}

func LoadDynamic() {
	C.ENGINE_load_dynamic()
}

// Engine wraps an openssl ENGINE
type Engine struct {
	eng *C.ENGINE
}

func (e *Engine) GetCEngine() *C.ENGINE {
	return e.eng
}

// New instantiates a new engine and adds a "destuctor hook" to it
func New(e *C.ENGINE) *Engine {
	if e == nil {
		return nil
	}
	eng := &Engine{eng: e}
	runtime.SetFinalizer(eng, freeEngine)
	return eng
}

func freeEngine(e *Engine) {
	C.ENGINE_free(e.eng)
}

func NewFirst() *Engine {
	return New(C.ENGINE_get_first())
}

func NewLast() *Engine {
	return New(C.ENGINE_get_last())
}

func NewById(id string) *Engine {
	eid := C.CString(id)
	defer C.free(unsafe.Pointer(eid))
	return New(C.ENGINE_by_id(eid))
}

//functional engines are just like regular engines but require
//engine_finish rather than engine_free to be called I guess.
func NewFunctional(e *C.ENGINE) *Engine {
	if e == nil {
		return nil
	}
	eng := &Engine{eng: e}
	runtime.SetFinalizer(eng, finishEngine)
	return eng
}

func finishEngine(e *Engine) {
	C.ENGINE_finish(e.eng)
}

func NewFunctionalDefaultRSA() *Engine {
	return NewFunctional(C.ENGINE_get_default_RSA())
}

func NewFunctionalDefaultDSA() *Engine {
	return NewFunctional(C.ENGINE_get_default_DSA())
}

func NewFunctionalDefaultECDH() *Engine {
	return NewFunctional(C.ENGINE_get_default_ECDH())
}

func NewFunctionalDefaultECDSA() *Engine {
	return NewFunctional(C.ENGINE_get_default_ECDSA())
}

func NewFunctionalDefaultRAND() *Engine {
	return NewFunctional(C.ENGINE_get_default_RAND())
}

func NewFunctionalByCipherEngine(nid int) *Engine {
	return NewFunctional(C.ENGINE_get_cipher_engine(C.int(nid)))
}

func NewFunctionalByDigestEngine(nid int) *Engine {
	return NewFunctional(C.ENGINE_get_digest_engine(C.int(nid)))
}

func NewFunctionalByPKeyMethEngine(nid int) *Engine {
	return NewFunctional(C.ENGINE_get_pkey_meth_engine(C.int(nid)))
}

func NewFunctionalByPKeyASN1MethEngine(nid int) *Engine {
	return NewFunctional(C.ENGINE_get_pkey_asn1_meth_engine(C.int(nid)))
}

func (e *Engine) GetPrev() *Engine {
	return New(C.ENGINE_get_prev(e.eng))
}

func (e *Engine) GetNext() *Engine {
	return New(C.ENGINE_get_next(e.eng))
}

func (e *Engine) Remove() int {
	return int(C.ENGINE_remove(e.eng))
}

func (e *Engine) Add() int {
	return int(C.ENGINE_add(e.eng))
}

func (e *Engine) ID() string {
	return C.GoString(C.ENGINE_get_id(e.eng))
}

func (e *Engine) Name() string {
	return C.GoString(C.ENGINE_get_name(e.eng))
}

func (e *Engine) Flags() int {
	return int(C.ENGINE_get_flags(e.eng))
}

func Cleanup() {
	C.ENGINE_cleanup()
}

func SetDefaultRSA(e *Engine) int {
	return int(C.ENGINE_set_default_RSA(e.eng))
}

func SetDefaultDSA(e *Engine) int {
	return int(C.ENGINE_set_default_DSA(e.eng))
}

func SetDefaultECDH(e *Engine) int {
	return int(C.ENGINE_set_default_ECDH(e.eng))
}

func SetDefaultECDSA(e *Engine) int {
	return int(C.ENGINE_set_default_ECDSA(e.eng))
}

func SetDefaultDH(e *Engine) int {
	return int(C.ENGINE_set_default_DH(e.eng))
}

func SetDefaultRAND(e *Engine) int {
	return int(C.ENGINE_set_default_RAND(e.eng))
}

func SetDefaultCiphers(e *Engine) int {
	return int(C.ENGINE_set_default_ciphers(e.eng))
}

func SetDefaultDigests(e *Engine) int {
	return int(C.ENGINE_set_default_digests(e.eng))
}

func SetDefaultPKeyMeths(e *Engine) int {
	return int(C.ENGINE_set_default_pkey_meths(e.eng))
}

func SetDefaultPKeyASN1Meths(e *Engine) int {
	return int(C.ENGINE_set_default_pkey_asn1_meths(e.eng))
}
