package openssl

import "testing"

var encoded_cert string = `-----BEGIN CERTIFICATE-----
MIIDIDCCAggCCQDoMvVcAzz25jANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJV
UzENMAsGA1UECAwEVXRhaDEXMBUGA1UEBwwOU2FsdCBMYWtlIENpdHkxDzANBgNV
BAoMBmdvLXNzbDEKMAgGA1UEAwwBKjAeFw0xMjA3MTIwNDA4NDRaFw0xMzA3MTIw
NDA4NDRaMFIxCzAJBgNVBAYTAlVTMQ0wCwYDVQQIDARVdGFoMRcwFQYDVQQHDA5T
YWx0IExha2UgQ2l0eTEPMA0GA1UECgwGZ28tc3NsMQowCAYDVQQDDAEqMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvcl+PqBRBBnWCUwch9Yx/RSP2tGx
MVo3FCQzcri3y/PldIJBOK6Pyj92E/q+jUzcCPCruGZDp+fNj3vJ7/pnagP8UYNe
h1jAIFTNm8xP0SkV8EiDqQ1CJjpdksFl4N27Y+TpLuKh//bhvS1v+wQf4zArczz2
AB0OXpCTvzqBoDneUMy+9dHIoND+khMNhSG9EAHEz41k/kv6klqi/58a4GWBeSch
PPQvmkzZ74i2LYV+S65jqEurjSCIJ+gsR9TKlVIel6xsO716BhORWIvIsUsbq1bK
PCZlBfDheSUKyKXZdxBt4V8Qi4N0ya1aYmqpbU+DkvHHz6Ti+5AlpmEEswIDAQAB
MA0GCSqGSIb3DQEBBQUAA4IBAQC8khevVR9HuMl8SdnCqDNi/r8TEk5ws/pZoilq
ygLNOQhaX3MuIrSDehG8rbgO0MulApJmSBRkst0V4E87M6B0yJRd5iKgJ3r+gOor
0etScut3ltD2C1RvUJIJyMeqsc3LtpoRBJ75gJAg+f+LBTztkukl3h7UzU8f7Y8r
Kk6LtCVglz5jTPQTU73wZM8jSFQP1UtfKuPHnj3VL/gcaZDD6yZi4AEFrYvkSZv6
2JvhVTHLbggl13T2cTWWyHCi/lb7ZukdzdZsjE9aBt+tl0X8f6WNlr28Ru2o9DpN
9f0NVVtxL3phxJEqWfPyKGodiwJZC9qN3fNXiHdvqZHZbQ28
-----END CERTIFICATE-----`

func TestParseCertificate(t *testing.T) {
    cert, err := ParseCertificatePEM([]byte(encoded_cert))
    if err != nil {
        t.Fatal("couldn't parse cert")
    }
    _, err = cert.DumpDERCertificate()
    if err != nil {
        t.Fatal("couldn't serialize cert")
    }
}
