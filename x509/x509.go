package x509

/*
#cgo pkg-config: openssl
#include <openssl/pem.h>
#include <openssl/x509.h>

#define d2i_X509_f 0
#define d2i_X509_REQ_f 1

static void *__d2i_X509_f_with_counter(unsigned int f, const unsigned char **in, long length, long *counter)
{
	const unsigned char *p = *in + *counter;
	void *c = NULL;

	switch (f) {
	case d2i_X509_f:
		c = d2i_X509(NULL, &p, length);
		break;
	case d2i_X509_REQ_f:
		c = d2i_X509_REQ(NULL, &p, length);
		break;
	default:
		break;
	}
	if (c == NULL)
		return NULL;
	*counter = p - *in;
	return c;
}

static X509 *d2i_X509_with_counter(const unsigned char **in, long length, long *counter)
{
	return (X509 *)__d2i_X509_f_with_counter(d2i_X509_f, in, length, counter);
}

static X509_REQ *d2i_X509_REQ_with_counter(const unsigned char **in, long length, long *counter)
{
	return (X509_REQ *)__d2i_X509_f_with_counter(d2i_X509_REQ_f, in, length, counter);
}

static int X509_get_version_no_macro(X509 *cert)
{
	return X509_get_version(cert);
}
*/
import "C"
import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"unsafe"

	"github.com/shanemhansen/gossl/sslerr"
)

type PEMCipher int

// Possible values for the EncryptPEMBlock encryption algorithm.
const (
	_ PEMCipher = iota
	PEMCipherDES
	PEMCipher3DES
	PEMCipherAES128
	PEMCipherAES192
	PEMCipherAES256
)

// A Certificate represents an X.509 certificate.
type Certificate struct {
	x509 *C.X509
	Raw  []byte

	Version      int
	SerialNumber *big.Int
	Issuer       string
	Subject      string

	//TODO(runcom): add more pub fields
}

// ParseCertificate parses a single certificate from the given ASN.1 DER data.
func ParseCertificate(asn1Data []byte) (*Certificate, error) {
	var (
		c       *C.X509
		dlen    = C.long(len(asn1Data))
		buf     = (*C.uchar)(&asn1Data[0])
		counter = C.long(0)
	)
	c = C.d2i_X509_with_counter(&buf, dlen, &counter)
	if c == nil {
		return nil, errors.New("error parsing der data: " + sslerr.SSLErrorMessage().String())
	}
	cert, err := getCertificate(asn1Data[:counter], c)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// ParseCertificates parses one or more certificates from the given ASN.1 DER
// data. The certificates must be concatenated with no intermediate padding.
func ParseCertificates(asn1Data []byte) ([]*Certificate, error) {
	var (
		cs      []*Certificate
		dlen    = C.long(len(asn1Data))
		buf     = (*C.uchar)(&asn1Data[0])
		counter = C.long(0)
		prev    int
	)
	for counter < dlen {
		c := C.d2i_X509_with_counter(&buf, dlen, &counter)
		if c == nil {
			return nil, errors.New("error parsing der data: " + sslerr.SSLErrorMessage().String())
		}
		cert, err := getCertificate(asn1Data[prev:counter], c)
		if err != nil {
			return nil, err
		}
		cs = append(cs, cert)
		prev = int(counter)
	}
	return cs, nil
}

func getCertificate(asn1Data []byte, x509 *C.X509) (*Certificate, error) {
	cert := &Certificate{}
	cert.x509 = x509
	// certificate raw data
	cert.Raw = asn1Data
	// certificate version (zero indexed)
	cert.Version = int(C.X509_get_version_no_macro(cert.x509)) + 1
	// certificate serial number
	cert.SerialNumber = big.NewInt(int64(C.ASN1_INTEGER_get(C.X509_get_serialNumber(cert.x509))))
	// TODO(runcom): store in pkix.Name
	// certificate subject
	cert.Subject = C.GoString(C.X509_NAME_oneline(C.X509_get_subject_name(cert.x509), nil, 0))
	// TODO(runcom): store in pkix.Name
	// certificate issuer
	cert.Issuer = C.GoString(C.X509_NAME_oneline(C.X509_get_issuer_name(cert.x509), nil, 0))
	return cert, nil
}

// CertificateRequest represents a PKCS #10, certificate signature request.
type CertificateRequest struct {
	req *C.X509_REQ

	//TODO(runcom): add more pub fields
}

// ParseCertificateRequest parses a single certificate request from the
// given ASN.1 DER data.
func ParseCertificateRequest(asn1Data []byte) (*CertificateRequest, error) {
	var (
		cr      *C.X509_REQ
		dlen    = C.long(len(asn1Data))
		buf     = (*C.uchar)(&asn1Data[0])
		counter = C.long(0)
	)
	cr = C.d2i_X509_REQ_with_counter(&buf, dlen, &counter)
	if cr == nil {
		return nil, errors.New("error parsing der data: " + sslerr.SSLErrorMessage().String())
	}
	certReq, err := getCertificateRequest(asn1Data[:counter], cr)
	if err != nil {
		return nil, err
	}
	return certReq, nil
}

func getCertificateRequest(asn1Data []byte, req *C.X509_REQ) (*CertificateRequest, error) {
	cr := &CertificateRequest{}
	cr.req = req
	return cr, nil
}

// pemCRLPrefix is the magic string that indicates that we have a PEM encoded
// CRL.
var pemCRLPrefix = []byte("-----BEGIN X509 CRL")

// ParseCRL parses a CRL from the given bytes. It's often the case that PEM
// encoded CRLs will appear where they should be DER encoded, so this function
// will transparently handle PEM encoding as long as there isn't any leading
// garbage.
func ParseCRL(crlBytes []byte) (certList *pkix.CertificateList, err error) {
	if bytes.HasPrefix(crlBytes, pemCRLPrefix) {
		var (
			crl  *C.X509_CRL
			buf  = unsafe.Pointer(&crlBytes[0])
			blen = C.int(len(crlBytes))
			bio  = C.BIO_new_mem_buf(buf, blen)
		)
		crl = C.PEM_read_bio_X509_CRL(bio, nil, nil, nil)
		if crl != nil {
			// use crl
			return &pkix.CertificateList{}, nil
		}
	}
	return ParseDERCRL(crlBytes)
}

// ParseDERCRL parses a DER encoded CRL from the given bytes.
func ParseDERCRL(derBytes []byte) (certList *pkix.CertificateList, err error) {
	var (
		crl  *C.X509_CRL
		buf  = unsafe.Pointer(&derBytes[0])
		blen = C.int(len(derBytes))
		bio  = C.BIO_new_mem_buf(buf, blen)
	)
	crl = C.d2i_X509_CRL_bio(bio, nil)
	if crl == nil {
		return nil, errors.New("error parsing der data: " + sslerr.SSLErrorMessage().String())
	}
	// use crl
	return &pkix.CertificateList{}, nil
}

func certificateListFromCRL(crl *C.X509_CRL) *pkix.CertificateList {
	return &pkix.CertificateList{}
}

// IncorrectPasswordError is returned when an incorrect password is detected.
var IncorrectPasswordError = errors.New("x509: decryption password incorrect")

// DecryptPEMBlock takes a password encrypted PEM block and the password used to
// encrypt it and returns a slice of decrypted DER encoded bytes. It inspects
// the DEK-Info header to determine the algorithm used for decryption. If no
// DEK-Info header is present, an error is returned. If an incorrect password
// is detected an IncorrectPasswordError is returned. Because of deficiencies
// in the encrypted-PEM format, it's not always possible to detect an incorrect
// password. In these cases no error will be returned but the decrypted DER
// bytes will be random noise.
func DecryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	var (
		raw = b.Bytes
	)
	_ = raw

	return nil, nil
}

// EncryptPEMBlock returns a PEM block of the specified type holding the
// given DER-encoded data encrypted with the specified algorithm and
// password.
func EncryptPEMBlock(rand io.Reader, blockType string, data, password []byte, alg PEMCipher) (*pem.Block, error) {
	return nil, nil
}

// IsEncryptedPEMBlock returns if the PEM block is password encrypted.
func IsEncryptedPEMBlock(b *pem.Block) bool {
	return x509.IsEncryptedPEMBlock(b)
}
