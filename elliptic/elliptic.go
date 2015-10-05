// Package elliptic implements several standard elliptic curves over prime
// fields. Note that not all curves are supported everywhere (e.g. RHEL/Fedora).
package elliptic

/*
#cgo pkg-config: openssl
#include <stdlib.h>
#include <openssl/obj_mac.h>
#include <openssl/objects.h>
#include <openssl/ec.h>
*/
import "C"
import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"
	"reflect"
	"sync"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

var availableCurves map[C.int]bool

func init() {
	var (
		l  = C.size_t(1001)
		bi = make([]C.EC_builtin_curve, l)
		n  = int(C.EC_get_builtin_curves(&bi[0], l))
	)
	availableCurves = make(map[C.int]bool)
	for i := 0; i < n; i++ {
		availableCurves[bi[i].nid] = true
	}
}

// CurveParams contains the parameters of an elliptic curve
type CurveParams struct {
	*elliptic.CurveParams

	curve *C.EC_GROUP
}

func (curve CurveParams) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve CurveParams) IsOnCurve(x, y *big.Int) bool {
	bnx := C.BN_new()
	if bnx == nil {
		return false
	}
	defer C.BN_free(bnx)
	bny := C.BN_new()
	if bny == nil {
		return false
	}
	defer C.BN_free(bny)

	xs := C.CString(x.String())
	defer C.free(unsafe.Pointer(xs))
	if C.BN_hex2bn(&bnx, xs) == 0 {
		return false
	}
	ys := C.CString(y.String())
	defer C.free(unsafe.Pointer(ys))
	if C.BN_hex2bn(&bny, ys) == 0 {
		return false
	}

	point := C.EC_POINT_new(curve.curve)
	if point == nil {
		return false
	}
	defer C.EC_POINT_free(point)

	if C.EC_POINT_set_affine_coordinates_GFp(curve.curve, point, bnx, bny, nil) != 1 {
		return false
	}
	if C.EC_POINT_is_on_curve(curve.curve, point, nil) == 0 {
		return false
	}
	return true
}

func (curve CurveParams) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	bnx1 := C.BN_new()
	if bnx1 == nil {
		return nil, nil
	}
	defer C.BN_free(bnx1)
	bny1 := C.BN_new()
	if bny1 == nil {
		return nil, nil
	}
	defer C.BN_free(bny1)
	bnx2 := C.BN_new()
	if bnx2 == nil {
		return nil, nil
	}
	defer C.BN_free(bnx2)
	bny2 := C.BN_new()
	if bny2 == nil {
		return nil, nil
	}
	defer C.BN_free(bny2)

	x1s := C.CString(x1.String())
	defer C.free(unsafe.Pointer(x1s))
	if C.BN_hex2bn(&bnx1, x1s) == 0 {
		return nil, nil
	}
	y1s := C.CString(y1.String())
	defer C.free(unsafe.Pointer(y1s))
	if C.BN_hex2bn(&bny1, y1s) == 0 {
		return nil, nil
	}
	x2s := C.CString(x2.String())
	defer C.free(unsafe.Pointer(x2s))
	if C.BN_hex2bn(&bnx2, x2s) == 0 {
		return nil, nil
	}
	y2s := C.CString(y2.String())
	defer C.free(unsafe.Pointer(y2s))
	if C.BN_hex2bn(&bny2, y2s) == 0 {
		return nil, nil
	}

	pointR := C.EC_POINT_new(curve.curve)
	if pointR == nil {
		return nil, nil
	}
	defer C.EC_POINT_free(pointR)

	pointA := C.EC_POINT_new(curve.curve)
	if pointA == nil {
		return nil, nil
	}
	defer C.EC_POINT_free(pointA)
	if C.EC_POINT_set_affine_coordinates_GFp(curve.curve, pointA, bnx1, bny1, nil) != 1 {
		return nil, nil
	}

	pointB := C.EC_POINT_new(curve.curve)
	if pointB == nil {
		return nil, nil
	}
	defer C.EC_POINT_free(pointB)
	if C.EC_POINT_set_affine_coordinates_GFp(curve.curve, pointB, bnx2, bny2, nil) != 1 {
		return nil, nil
	}

	if C.EC_POINT_add(curve.curve, pointR, pointA, pointB, nil) == 0 {
		return nil, nil
	}

	bnx := C.BN_new()
	if bnx == nil {
		return nil, nil
	}
	defer C.BN_free(bnx)
	bny := C.BN_new()
	if bny == nil {
		return nil, nil
	}
	defer C.BN_free(bny)

	if C.EC_POINT_get_affine_coordinates_GFp(curve.curve, pointR, bnx, bny, nil) != 1 {
		return nil, nil
	}
	x, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(bnx)), 16)
	y, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(bny)), 16)

	return
}

func (curve CurveParams) Double(x1, y1 *big.Int) (x, y *big.Int) {
	bnx1 := C.BN_new()
	if bnx1 == nil {
		return nil, nil
	}
	defer C.BN_free(bnx1)
	bny1 := C.BN_new()
	if bny1 == nil {
		return nil, nil
	}
	defer C.BN_free(bny1)

	x1s := C.CString(x1.String())
	defer C.free(unsafe.Pointer(x1s))
	if C.BN_hex2bn(&bnx1, x1s) == 0 {
		return nil, nil
	}
	y1s := C.CString(y1.String())
	defer C.free(unsafe.Pointer(y1s))
	if C.BN_hex2bn(&bny1, y1s) == 0 {
		return nil, nil
	}

	pointR := C.EC_POINT_new(curve.curve)
	if pointR == nil {
		return nil, nil
	}
	defer C.EC_POINT_free(pointR)

	pointA := C.EC_POINT_new(curve.curve)
	if pointA == nil {
		return nil, nil
	}
	defer C.EC_POINT_free(pointA)
	if C.EC_POINT_set_affine_coordinates_GFp(curve.curve, pointA, bnx1, bny1, nil) != 1 {
		return nil, nil
	}

	if C.EC_POINT_dbl(curve.curve, pointR, pointA, nil) == 0 {
		return nil, nil
	}

	bnx := C.BN_new()
	if bnx == nil {
		return nil, nil
	}
	defer C.BN_free(bnx)
	bny := C.BN_new()
	if bny == nil {
		return nil, nil
	}
	defer C.BN_free(bny)

	if C.EC_POINT_get_affine_coordinates_GFp(curve.curve, pointR, bnx, bny, nil) != 1 {
		return nil, nil
	}
	x, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(bnx)), 16)
	y, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(bny)), 16)

	return
}

func (curve CurveParams) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	bnx1 := C.BN_new()
	if bnx1 == nil {
		return nil, nil
	}
	defer C.BN_free(bnx1)
	bny1 := C.BN_new()
	if bny1 == nil {
		return nil, nil
	}
	defer C.BN_free(bny1)

	x1s := C.CString(x1.String())
	defer C.free(unsafe.Pointer(x1s))
	if C.BN_hex2bn(&bnx1, x1s) == 0 {
		return nil, nil
	}
	y1s := C.CString(y1.String())
	defer C.free(unsafe.Pointer(y1s))
	if C.BN_hex2bn(&bny1, y1s) == 0 {
		return nil, nil
	}

	pointR := C.EC_POINT_new(curve.curve)
	if pointR == nil {
		return nil, nil
	}
	defer C.EC_POINT_free(pointR)

	pointQ := C.EC_POINT_new(curve.curve)
	if pointQ == nil {
		return nil, nil
	}
	defer C.EC_POINT_free(pointQ)
	if C.EC_POINT_set_affine_coordinates_GFp(curve.curve, pointQ, bnx1, bny1, nil) != 1 {
		return nil, nil
	}

	n := C.BN_new()
	if n == nil {
		return nil, nil
	}
	defer C.BN_free(n)

	bn := C.CString(string(k))
	defer C.free(unsafe.Pointer(bn))
	if C.BN_hex2bn(&n, bn) == 0 {
		return nil, nil
	}

	if C.EC_POINT_mul(curve.curve, pointR, n, pointQ, nil, nil) != 1 {
		return nil, nil
	}

	rx := C.BN_new()
	if rx == nil {
		return nil, nil
	}
	defer C.BN_free(rx)
	ry := C.BN_new()
	if ry == nil {
		return nil, nil
	}
	defer C.BN_free(ry)
	if C.EC_POINT_get_affine_coordinates_GFp(curve.curve, pointR, rx, ry, nil) != 1 {
		return nil, nil
	}
	x, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(rx)), 16)
	y, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(ry)), 16)

	return
}

func (curve CurveParams) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Params().Gx, curve.Params().Gy, k)
}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
// TODO(runcom): add support for Go stdlib `elliptic.Curve`, for now unsupported
func GenerateKey(curve elliptic.Curve, rand io.Reader) (priv []byte, x, y *big.Int, err error) {
	// rand isn't used with openssl...

	// for go stdlib compatibility
	//c, _ := curve.(*elliptic.CurveParams)

	// to use this pkg
	c, ok := curve.(CurveParams)
	if !ok {
		return nil, nil, nil, errors.New("provided curve is unsupported")
	}

	k := C.EC_KEY_new()
	if k == nil {
		return nil, nil, nil, errors.New("can't create key")
	}
	defer C.EC_KEY_free(k)

	if C.EC_KEY_set_group(k, c.curve) != 1 {
		return nil, nil, nil, errors.New("can't set ec_group on key")
	}

	if C.EC_KEY_generate_key(k) != 1 {
		return nil, nil, nil, errors.New("can't generate key")
	}

	blen := C.i2d_ECPrivateKey(k, nil)
	if blen == 0 {
		return nil, nil, nil, errors.New("can't get private key")
	}
	buf := make([]C.uchar, int(blen))
	pkey := (*C.uchar)(&buf[0])
	if C.i2d_ECPrivateKey(k, &pkey) == 0 {
		return nil, nil, nil, errors.New("can't get private key")
	}

	point := C.EC_KEY_get0_public_key(k)
	if point == nil {
		return nil, nil, nil, errors.New("can't get public key")
	}
	defer C.EC_POINT_free(point)

	rx := C.BN_new()
	if rx == nil {
		return nil, nil, nil, errors.New("error creating big num")
	}
	defer C.BN_free(rx)
	ry := C.BN_new()
	if ry == nil {
		return nil, nil, nil, errors.New("errors creating big num")
	}
	defer C.BN_free(ry)
	if C.EC_POINT_get_affine_coordinates_GFp(c.curve, point, rx, ry, nil) != 1 {
		return nil, nil, nil, errors.New("can't get public key")
	}
	x, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(rx)), 16)
	y, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(ry)), 16)

	priv = C.GoBytes(unsafe.Pointer(pkey), C.int(blen))

	return priv, x, y, nil
}

// Marshal converts a point into the form specified in section 4.3.6 of ANSI X9.62.
func Marshal(curve elliptic.Curve, x, y *big.Int) []byte {
	// TODO(runcom): couldn't find anything in openssl
	return nil
}

// Unmarshal converts a point, serialized by Marshal, into an x, y pair.
// It is an error if the point is not on the curve. On error, x = nil.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	// TODO(runcom): couldn't find anything in openssl
	return nil, nil
}

var (
	initonce sync.Once
	p224     CurveParams
	p256     CurveParams
	p384     CurveParams
	p521     CurveParams
)

func initAll() {
	initP224()
	initP256()
	initP384()
	initP521()
}

func initP224() {
	curve := newCurve(C.NID_secp224r1)
	if curve == nil {
		return
	}
	p224.curve = curve
	p224.CurveParams = buildCurveParams(p224.curve)
}

func initP256() {
	curve := newCurve(C.NID_secp256k1)
	if curve == nil {
		return
	}
	p256.curve = curve
	p256.CurveParams = buildCurveParams(p256.curve)
	// TODO(runcom): add finalizer? runtime errors last time, will check
	// and these are global vars, no need probably
}

func initP384() {
	curve := newCurve(C.NID_secp384r1)
	if curve == nil {
		return
	}
	p384.curve = curve
	p384.CurveParams = buildCurveParams(p384.curve)
}

func initP521() {
	curve := newCurve(C.NID_secp521r1)
	if curve == nil {
		return
	}
	p521.curve = curve
	p521.CurveParams = buildCurveParams(p521.curve)
}

func newCurve(nid C.int) *C.EC_GROUP {
	if !availableCurves[nid] {
		return nil
	}
	curve := C.EC_GROUP_new_by_curve_name(nid)
	if curve == nil {
		panic("problem creating ec: " + sslerr.SSLErrorMessage().String())
	}
	return curve
}

func buildCurveParams(curve *C.EC_GROUP) *elliptic.CurveParams {
	cp := &elliptic.CurveParams{}
	// handle go < 1.5
	// Name wasn't in CurveParams before
	elem := reflect.ValueOf(cp).Elem()
	f := elem.FieldByName("Name")
	if f.IsValid() {
		f.SetString(getCurveName(curve))
	}
	cp.BitSize = getCurveBitSize(curve)

	p := C.BN_new()
	if p == nil {
		panic(sslerr.SSLErrorMessage().String())
	}
	defer C.BN_free(p)
	a := C.BN_new()
	if a == nil {
		panic(sslerr.SSLErrorMessage().String())
	}
	defer C.BN_free(a)
	b := C.BN_new()
	if b == nil {
		panic(sslerr.SSLErrorMessage().String())
	}
	defer C.BN_free(b)

	if C.EC_GROUP_get_curve_GFp(curve, p, a, b, nil) != 1 {
		panic(sslerr.SSLErrorMessage().String())
	}
	if p == nil || a == nil || b == nil {
		panic("something went wrong getting GFp params")
	}
	cp.P, _ = new(big.Int).SetString(C.GoString(C.BN_bn2dec(p)), 10)
	cp.N, _ = new(big.Int).SetString(C.GoString(C.BN_bn2dec(a)), 10)
	cp.B, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(b)), 16)

	generator := C.EC_GROUP_get0_generator(curve)
	if generator == nil {
		panic("generator cannot be nil")
	}
	x := C.BN_new()
	if x == nil {
		panic(sslerr.SSLErrorMessage().String())
	}
	defer C.BN_free(x)
	y := C.BN_new()
	if y == nil {
		panic(sslerr.SSLErrorMessage().String())
	}
	defer C.BN_free(y)
	if C.EC_POINT_get_affine_coordinates_GFp(curve, generator, x, y, nil) != 1 {
		panic(sslerr.SSLErrorMessage().String())
	}
	if x == nil || y == nil {
		panic("something went wrong getting affine coordinates")
	}
	cp.Gx, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(x)), 16)
	cp.Gy, _ = new(big.Int).SetString(C.GoString(C.BN_bn2hex(y)), 16)

	return cp
}

func getCurveName(curve *C.EC_GROUP) string {
	return C.GoString(C.OBJ_nid2sn(C.EC_GROUP_get_curve_name(curve)))
}

func getCurveBitSize(curve *C.EC_GROUP) int {
	return int(C.EC_GROUP_get_degree(curve))
}

// IsSupported is a shorthand to check if the given curve is supported on your
// system.
func IsSupported(curve elliptic.Curve) bool {
	return curve.Params() != (*elliptic.CurveParams)(nil)
}

// P256 returns a Curve which implements P-256 (see FIPS 186-3, section D.2.3)
// If the returned curve is nil then it's unsupported on your system.
func P256() elliptic.Curve {
	initonce.Do(initAll)
	return p256
}

// P384 returns a Curve which implements P-384 (see FIPS 186-3, section D.2.4)
// If the returned curve is nil then it's unsupported on your system.
func P384() elliptic.Curve {
	initonce.Do(initAll)
	return p384
}

// P521 returns a Curve which implements P-521 (see FIPS 186-3, section D.2.5)
// If the returned curve is nil then it's unsupported on your system.
func P521() elliptic.Curve {
	initonce.Do(initAll)
	return p521
}
