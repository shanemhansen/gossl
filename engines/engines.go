// Package engines provides an interface to the OpenSSL engines api.
// Mostly useful for enabling disabling hardware acceleration afaik.
// See http://www.openssl.org/docs/crypto/engine.html
package engines
/*
#cgo pkg-config: openssl
#include "openssl/engine.h"
*/
import "C"
import "fmt"
import "unsafe"
import "runtime"
var Init int = func() int {
    C.ERR_load_ENGINE_strings(); return 1
}()

func LoadBuiltinEngines() {
    C.ENGINE_load_builtin_engines()
}
func LoadCryptodev() {
    C.ENGINE_load_cryptodev()
}
func LoadRsax() {
    C.ENGINE_load_rsax()
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

type ENGINE struct {
    engine *C.ENGINE
}
func (self *ENGINE) String() (string) {
    return fmt.Sprintf("<id:%s @%p>", self.id(), self)
}
//instantiates a new engine and adds a "destuctor hook"
func newEngine(engine *C.ENGINE) (*ENGINE) {
    if engine == nil {
        return nil
    }
    e := ENGINE{engine}
    runtime.SetFinalizer(&e, freeEngine)
    return &e
}
func freeEngine(self *ENGINE) {
    C.ENGINE_free(self.engine)
    return
}
func GetFirst() (*ENGINE) {
    return newEngine(C.ENGINE_get_first())
}
func GetLast() (*ENGINE) {
    return newEngine(C.ENGINE_get_last())
}
func ById(id string) (*ENGINE) {
    id_p := C.CString(id)
    defer C.free(unsafe.Pointer(id_p))
    return newEngine(C.ENGINE_by_id(id_p))
}
func Cleanup() {
    C.ENGINE_cleanup()
}

//structural reference methods
func (self *ENGINE) GetPrev() (*ENGINE) {
    return newEngine(C.ENGINE_get_prev(self.engine))
}
func (self *ENGINE) GetNext() (*ENGINE) {
    return newEngine(C.ENGINE_get_next(self.engine))
}
func (self *ENGINE) remove() int {
    return int(C.ENGINE_remove(self.engine))
}
func (self *ENGINE) add() int {
    return int(C.ENGINE_add(self.engine))
}
func (self *ENGINE) id() string {
    return C.GoString(C.ENGINE_get_id(self.engine))
}
func (self *ENGINE) name() string {
    return C.GoString(C.ENGINE_get_name(self.engine))
}
func (self *ENGINE) flags() int {
    return int(C.ENGINE_get_flags(self.engine))
}
//these methods interrogate the OpenSSL library to getermine what
//operations they are using.
func finishEngine(self *ENGINE) {
    C.ENGINE_finish(self.engine)
    return
}
//functional engines are just like regular engines but require
//engine_finish rather than engine_free to be called I guess.
func newFunctionalEngine(engine *C.ENGINE) (*ENGINE) {
    if engine == nil {
        return nil
    }
    e := ENGINE{engine}
    runtime.SetFinalizer(&e, finishEngine)
    return &e
}
//get the default RSA implmentation
func GetDefaultRSA() (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_default_RSA())
}
func GetDefaultDSA() (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_default_DSA())
}
func GetDefaultECDH() (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_default_ECDH())
}
func GetDefaultECDSA() (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_default_ECDSA())
}
func GetDefaultRAND() (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_default_RAND())
}
func GetCipherEngine(nid int) (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_cipher_engine(C.int(nid)))
}
func GetDigestEngine(nid int) (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_digest_engine(C.int(nid)))
}
func GetPKeyMethEngine(nid int) (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_pkey_meth_engine(C.int(nid)))
}
func GetPKeyASN1MethEngine(nid int) (*ENGINE) {
    return newFunctionalEngine(C.ENGINE_get_pkey_asn1_meth_engine(C.int(nid)))
}
//these set default engines for RSA operations
func SetDefaultRSA(engine *ENGINE) int {
    return int(C.ENGINE_set_default_RSA(engine.engine))
}
func SetDefaultDSA(engine *ENGINE) int {
    return int(C.ENGINE_set_default_DSA(engine.engine))
}
func SetDefaultECDH(engine *ENGINE) int {
    return int(C.ENGINE_set_default_ECDH(engine.engine))
}
func SetDefaultECDSA(engine *ENGINE) int {
    return int(C.ENGINE_set_default_ECDSA(engine.engine))
}
func SetDefaultDH(engine *ENGINE) int {
    return int(C.ENGINE_set_default_DH(engine.engine))
}
func SetDefaultRAND(engine *ENGINE) int {
    return int(C.ENGINE_set_default_RAND(engine.engine))
}
func SetDefaultCiphers(engine *ENGINE) int {
    return int(C.ENGINE_set_default_ciphers(engine.engine))
}
func SetDefaultDigests(engine *ENGINE) int {
    return int(C.ENGINE_set_default_digests(engine.engine))
}
func SetDefaultPKeyMeths(engine *ENGINE) int {
    return int(C.ENGINE_set_default_pkey_meths(engine.engine))
}
func SetDefaultPKeyASN1Meths(engine *ENGINE) int {
    return int(C.ENGINE_set_default_pkey_asn1_meths(engine.engine))
}
