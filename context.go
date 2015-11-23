package gossl

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/stack.h"
*/
import "C"
import (
	"errors"
	"runtime"
	"time"
	"unsafe"

	"github.com/shanemhansen/gossl/crypto/evp"
	"github.com/shanemhansen/gossl/sslerr"
)

type Option int64

const (
	OpNoCompression Option = C.SSL_OP_NO_COMPRESSION
)

type FileType int

const (
	FileTypePem  FileType = C.SSL_FILETYPE_PEM
	FileTypeASN1 FileType = C.SSL_FILETYPE_ASN1
)

type Context struct {
	Ctx *C.SSL_CTX
}

func NewContext(method *METHOD) *Context {
	c := &Context{C.SSL_CTX_new(method.method)}
	runtime.SetFinalizer(c, contextFree)
	return c
}
func contextFree(self *Context) {
	C.SSL_CTX_free(self.Ctx)
}

func (self *Context) UsePrivateKey(key *evp.PKey) error {
	if int(C.SSL_CTX_use_PrivateKey(self.Ctx, (*C.EVP_PKEY)(unsafe.Pointer(key.PKey)))) != 1 {
		return errors.New("problem loading key " + sslerr.SSLErrorMessage().String())
	}
	return nil
}

func (self *Context) UseCertificate(cert *Certificate) error {

	if int(C.SSL_CTX_use_certificate(self.Ctx, (*C.X509)(unsafe.Pointer(cert.X509)))) != 1 {
		return errors.New("problem loading cert " + sslerr.SSLErrorMessage().String())
	}
	return nil
}

func (self *Context) UsePSKIdentityHint(hint string) int {
	return int(C.SSL_CTX_use_psk_identity_hint(self.Ctx, C.CString(hint)))
}

func (self *Context) SetAppData(data unsafe.Pointer) {
	C.SSL_CTX_set_ex_data(self.Ctx, 0, data)
}
func (self *Context) GetAppData() unsafe.Pointer {
	return C.SSL_CTX_get_ex_data(self.Ctx, 0)
}
func (self *Context) Ctrl(op int, op2 int, data unsafe.Pointer) int {
	return int(C.SSL_CTX_ctrl(self.Ctx, C.int(op), C.long(op2), data))
}
func (self *Context) SetCipherList(list string) int {
	return int(C.SSL_CTX_set_cipher_list(self.Ctx, C.CString(list)))
}
func (self *Context) SetTimeout(t time.Time) {
	C.SSL_CTX_set_timeout(self.Ctx, C.long(t.Unix()))
}
func (self *Context) GetTimeout() time.Time {
	return time.Unix(int64(C.SSL_CTX_get_timeout(self.Ctx)), 0)
}
func (self *Context) GetCertStore() *X509Store {
	return &X509Store{Store: C.SSL_CTX_get_cert_store(self.Ctx)}
}
func (self *Context) SetCertStore(store *X509Store) {
	C.SSL_CTX_set_cert_store(self.Ctx, store.Store)
}
func (self *Context) FlushSessions(t time.Time) {
	C.SSL_CTX_flush_sessions(self.Ctx, C.long(t.Unix()))
}
func (self *Context) UseRSAPrivateKeyFile(file string, filetype int) error {
	ret := int(C.SSL_CTX_use_RSAPrivateKey_file(self.Ctx,
		C.CString(file), C.int(filetype)))
	if ret != 1 {
		return errors.New(sslerr.SSLErrorMessage().String())
	}
	return nil

}
func (self *Context) SetOptions(options Option) {
	self.Ctrl(C.SSL_CTRL_OPTIONS, int(options), nil)
}
func (self *Context) GetOptions() int {
	return int(self.Ctrl(C.SSL_CTRL_OPTIONS, 0, nil))
}
func (self *Context) UsePrivateKeyFile(file string, filetype FileType) error {
	ret := int(C.SSL_CTX_use_PrivateKey_file(self.Ctx,
		C.CString(file), C.int(filetype)))
	if ret != 1 {
		return errors.New(sslerr.SSLErrorMessage().String())
	}
	return nil

}
func (self *Context) UseCertificateFile(file string, filetype FileType) error {
	ret := int(C.SSL_CTX_use_certificate_file(self.Ctx,
		C.CString(file), C.int(filetype)))
	if ret != 1 {
		return errors.New(sslerr.SSLErrorMessage().String())
	}
	return nil
}
func (self *Context) UseCertificateChainFile(file string) error {
	ret := int(C.SSL_CTX_use_certificate_chain_file(self.Ctx,
		C.CString(file)))
	if ret != 1 {
		return errors.New(sslerr.SSLErrorMessage().String())
	}
	return nil
}
func (self *Context) SetVerify(mode VerifyMode) {
	//TODO allow people to customize this
	C.SSL_CTX_set_verify(self.Ctx, C.int(mode), nil)
}
func (self *Context) SetVerifyDepth(depth int) {
	C.SSL_CTX_set_verify_depth(self.Ctx, C.int(depth))
}
func (self *Context) CheckPrivateKey() error {
	if int(C.SSL_CTX_check_private_key(self.Ctx)) != 1 {
		return errors.New(sslerr.SSLErrorMessage().String())
	}
	return nil
}
func (self *Context) SetSessionIdContext(ctx []byte) {
	C.SSL_CTX_set_session_id_context(self.Ctx,
		(*C.uchar)(unsafe.Pointer(&ctx[0])),
		C.uint(len(ctx)))
}
func (self *Context) SetPurpose(purpose int) int {
	return int(C.SSL_CTX_set_purpose(self.Ctx, C.int(purpose)))
}
func (self *Context) SetTrust(trust int) int {
	return int(C.SSL_CTX_set_trust(self.Ctx, C.int(trust)))
}
func (self *Context) SetClientCAList(names []X509Name) {
	s := C.sk_new(nil)
	for i := range names {
		C.sk_push(s, unsafe.Pointer(names[i].Name))
	}
	//This could go crashy
	//It's cutting through all the abstraction of SSL
	//Stacks because they are all macro based.
	C.SSL_CTX_set_client_CA_list(self.Ctx, (*C.struct_stack_st_X509_NAME)(unsafe.Pointer(s)))
}
func (self *Context) AddClientCA(cert *Certificate) int {
	return int(C.SSL_CTX_add_client_CA(self.Ctx, cert.X509))
}
func (self *Context) SetQuietShutdown(mode int) {
	C.SSL_CTX_set_quiet_shutdown(self.Ctx, C.int(mode))
}
func (self *Context) GetQuietShuwdown() int {
	return int(C.SSL_CTX_get_quiet_shutdown(self.Ctx))
}
func (self *Context) SetDefaultVerifyPaths() int {
	return int(C.SSL_CTX_set_default_verify_paths(self.Ctx))
}
func (self *Context) LoadVerifyLocations(cafile, capath *string) int {
	if cafile != nil && capath != nil {
		return int(C.SSL_CTX_load_verify_locations(self.Ctx,
			C.CString(*cafile), C.CString(*capath)))
	}
	if cafile == nil {
		return int(C.SSL_CTX_load_verify_locations(self.Ctx,
			nil, C.CString(*capath)))
	}
	if capath == nil {
		return int(C.SSL_CTX_load_verify_locations(self.Ctx,
			C.CString(*cafile), nil))
	}
	return -1
}
