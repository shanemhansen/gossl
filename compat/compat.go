//Package compat contains helper methods to interoperate with
//crypto/tls in the case where you just want to use gossl
//for parsing exotic keys.
package compat

import "io/ioutil"
import "net"
import "crypto/tls"
import "crypto/rsa"
import "crypto/x509"
import "errors"
import "github.com/shanemhansen/gossl"
import "github.com/shanemhansen/gossl/evp"
import "github.com/shanemhansen/gossl/sslerr"

//Wrap an existing listener + crypto config and return a new TLS enabled listener.
func NewListener(inner net.Listener, config *tls.Config) (net.Listener, error) {
    l := new(gossl.Listener)
    l.Listener = inner
    //FIXME hardcoded in method
    l.Context = gossl.NewContext(gossl.SSLv23Method())
    if l.Context == nil {
        msg := sslerr.SSLErrorMessage()
        return nil, errors.New("problem creating ssl context:\n" + msg)
    }
    //set certificates
    //grab the private key
    Kr := config.Certificates[0].PrivateKey
    private_key_der, err := extractDERKey(Kr)
    private_key, err := evp.LoadPrivateKeyDER(private_key_der)
    if err != nil {
        return nil, err
    }
    //set the private key into the context
    err = l.Context.UsePrivateKey(private_key)
    if err != nil {
        return nil, errors.New("problem loading key " + sslerr.SSLErrorMessage())
    }
    cert, err := gossl.ParseCertificate(config.Certificates[0].Certificate[0])
    if err != nil {
        return nil, err
    }
    err = l.Context.UseCertificate(cert)
    if err != nil {
        return nil, errors.New("problem loading key " + sslerr.SSLErrorMessage())
    }
    return l, nil
}

//Listen on network, laddr and return a listener that will handle TLS connections.
func Listen(network, laddr string, config *tls.Config) (net.Listener, error) {
    if config == nil || len(config.Certificates) == 0 {
        return nil, errors.New("tls.Listen: no certificates in configuration")
    }
    listener, err := net.Listen(network, laddr)
    if err != nil {
        return nil, err
    }
    return NewListener(listener, config)
}

//helper function to get the der bytes from a Kr object.
func extractDERKey(Kr interface{}) ([]byte, error) {
    var key *rsa.PrivateKey
    var ok bool
    //cast to rsa
    if key, ok = Kr.(*rsa.PrivateKey); !ok {
        return nil, errors.New("crypto/tls: found non-RSA private key")
    }
    //get the raw bytes
    private_key_der := x509.MarshalPKCS1PrivateKey(key)
    return private_key_der, nil

}

func LoadX509KeyPair(certpath, keypath string) (cert tls.Certificate, err error) {
    key_buf, err := ioutil.ReadFile(keypath)
    if err != nil {
        return
    }
    cert_buf, err := ioutil.ReadFile(certpath)
    if err != nil {
        return
    }
    pkey, err := evp.LoadPrivateKeyPEM(key_buf)
    if err != nil {
        return
    }
    key_buf, err = pkey.DumpPEM()
    return tls.X509KeyPair(cert_buf, key_buf)
}
