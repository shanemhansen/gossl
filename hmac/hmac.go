// Package hmac provides an interface to the OpenSSL hmac api to be compatible
// with Go's stdlib api.
// See http://www.openssl.org/docs/crypto/hmac.html
package hmac

/*
#cgo pkg-config: openssl
#include "openssl/hmac.h"
#include "openssl/engine.h"
*/
import "C"
import (
	"crypto"
	"crypto/subtle"
	"hash"
	"reflect"
	"runtime"
	"strings"
	"unsafe"

	"github.com/shanemhansen/gossl/engines"
	"github.com/shanemhansen/gossl/sslerr"
)

type hmac struct {
	ctx C.HMAC_CTX
}

// New returns a new HMAC hash using the given hash.Hash type and key.
// If the returned hash is `nil` make a call to `sslerr.Error()` to
// know what went wrong.
// Currently only `crypto.SHA512`, `crypto.SHA384`, `crypto.SHA256`,
// `crypto.SHA224`, `cryptoSHA1` and `crypto.MD5` are the only
// supported hashes. If an unsupported hash is provided it will cause a panic.
func New(h func() hash.Hash, key []byte) hash.Hash {
	return NewWithEngine(nil, h, key)
}

func NewWithEngine(e *engines.Engine, h func() hash.Hash, key []byte) hash.Hash {
	if h == nil {
		return nil
	}
	evp := getEVP(h())
	var eng *C.ENGINE
	if e != nil {
		eng = (*C.ENGINE)(e.GetCEngine())
	}
	hm := new(hmac)
	C.HMAC_CTX_init(&hm.ctx)
	if C.HMAC_Init_ex(&hm.ctx, unsafe.Pointer(C.CString(string(key))), C.int(len(key)), evp, eng) != 1 {
		return nil
	}
	runtime.SetFinalizer(hm, cleanup)
	return hm
}

// Equal compares two MACs for equality without leaking timing information.
func Equal(mac1, mac2 []byte) bool {
	return len(mac1) == len(mac2) && subtle.ConstantTimeCompare(mac1, mac2) == 1
}

func (hm *hmac) Write(msg []byte) (n int, err error) {
	size := C.size_t(len(msg))
	if C.HMAC_Update(&hm.ctx, (*C.uchar)(unsafe.Pointer(C.CString(string(msg)))), size) != 1 {
		return 0, sslerr.Error()
	}
	return len(msg), nil
}

// If the returned slice is empty make a call to sslerr.Error() to know what
// went wrong.
func (hm *hmac) Sum(b []byte) []byte {
	// store a copy to not lose it after each iteration
	var hmTmp C.HMAC_CTX
	C.HMAC_CTX_copy(&hmTmp, &hm.ctx)

	digest := make([]C.uchar, hm.Size())
	rlen := len(digest)
	if C.HMAC_Final(&hmTmp, &digest[0], (*C.uint)(unsafe.Pointer(&rlen))) != 1 {
		return make([]byte, 0)
	}

	var result []byte
	if b != nil {
		result = make([]byte, 0)
	} else {
		result = b
	}
	for _, value := range digest {
		result = append(result, byte(value))
	}
	return result
}

func (hm *hmac) Reset() {
	C.HMAC_Init_ex(&hm.ctx, nil, 0, nil, nil)
}

func (hm *hmac) Size() int {
	return int(C.EVP_MD_size(hm.ctx.md))
}

func (hm *hmac) BlockSize() int {
	return int(C.EVP_MD_block_size(hm.ctx.md))
}

func cleanup(hm *hmac) {
	// ignore error not to fail in a finalizer
	C.HMAC_CTX_cleanup(&hm.ctx)
}

func getEVP(h hash.Hash) *C.EVP_MD {
	hashName := getHashName(h)
	var evp *C.EVP_MD
	switch hashName {
	case "md5":
		evp = C.EVP_md5()
		break
	case "sha1":
		evp = C.EVP_sha1()
		break
	case "sha224":
		evp = C.EVP_sha224()
		break
	case "sha256":
		evp = C.EVP_sha256()
		break
	case "sha384":
		evp = C.EVP_sha384()
		break
	case "sha512":
		evp = C.EVP_sha512()
		break
	default:
		panic("unsupported hash: " + hashName)
	}
	return evp
}

// this is ugly.
func getHashName(h hash.Hash) string {
	hn := reflect.TypeOf(h).String()
	fields := strings.Split(hn, ".")
	var hashName string
	hashName = fields[0]
	if strings.HasPrefix(fields[0], "*") {
		hashName = fields[0][1:]
	}
	elem := reflect.ValueOf(h).Elem()
	switch hashName {
	case "sha256":
		is224 := elem.FieldByName("is224").Bool()
		if is224 {
			hashName = "sha224"
		}
		break
	case "sha512":
		d := elem.FieldByName("function").Uint()
		if crypto.Hash(d) == crypto.SHA384 {
			hashName = "sha384"
		}
		break
	}
	return hashName
}
