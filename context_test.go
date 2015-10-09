package gossl

import "testing"
import "github.com/shanemhansen/gossl/crypto/evp"

func TestContext(t *testing.T) {
	c := NewContext(SSLv3Method())
	pkey, err := evp.LoadPrivateKeyPEM(key_pem)
	cert, err := ParseCertificatePEM(cert_pem)
	if err != nil {
		t.Fatal(err)
	}
	c.UsePrivateKey(pkey)
	c.UseCertificate(cert)
	err = c.CheckPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	c.SetVerify(VERIFY_NONE)
	c.SetVerify(9)
	c.GetCertStore()
	// FIXME these are not tested after being set
}

var key_pem = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAvcl+PqBRBBnWCUwch9Yx/RSP2tGxMVo3FCQzcri3y/PldIJB
OK6Pyj92E/q+jUzcCPCruGZDp+fNj3vJ7/pnagP8UYNeh1jAIFTNm8xP0SkV8EiD
qQ1CJjpdksFl4N27Y+TpLuKh//bhvS1v+wQf4zArczz2AB0OXpCTvzqBoDneUMy+
9dHIoND+khMNhSG9EAHEz41k/kv6klqi/58a4GWBeSchPPQvmkzZ74i2LYV+S65j
qEurjSCIJ+gsR9TKlVIel6xsO716BhORWIvIsUsbq1bKPCZlBfDheSUKyKXZdxBt
4V8Qi4N0ya1aYmqpbU+DkvHHz6Ti+5AlpmEEswIDAQABAoIBAQC5H+20Ov8r5+O/
J+4AlnAmdMMp6DdWc7CcRf+lXQdzu5HLxy7FkokR+Ds+m+z5uco8Mj7e3WoLQ3Jh
DpfZLUFoyUB7ZpBzp5+pKe9xlKca2F/dBW7gHN20mmQiPeIZqVAbzfOjV1A8dN6X
gNXlXY2ZN6h6fTFcxPr6RT7JXtGIrpugq94wMiJXleE2QULmP2t04Ugce4CnF5Lv
MUKNb5FBjicZruii7jea5v7f58pfJZAIg6qyIfHreDTL6TscNXI5+Wz0R9sIxpmq
S+IeD74E0mK0rAbHDJerP6q7clCZRXhu+MtO+Q+ip1xbMUzILUfXOJ5tH4K/7zki
xSreWuopAoGBAORxmplP9lgfHPvCfY6hFsw0iBch+F+SCbLu38Sq/ic7kE8JzTx9
syO214hIwr8fcXibC8iEpXHGexhQvSbpXWBYxrV74ILTia93tEvEzorsK8s4qDdm
TUr6E/WrUiLcm8ph87Hm0L/OmLM07LYg2cltEp3ykY77o+Tg1OpQVAY3AoGBANSu
KXc5hC2D7s2HkWPvGygSM+kv1xmagLPzeXOuoYJ1Uis/VyENcaCxml6/LbC0/iwu
e+KPwAPQEIGFK6Al1ezPz1gnh9pU0VI3HUt88h8MeFd4xRsAmnSWFEvdeDG9aOqS
MKPO32OxVfht7fo5aZDrtGH3H4EyaFy6duAQ4XdlAoGAXHHgpzQls4l7uCH/n21v
BVoozHuxwDMf+6oRIcw0p3nCL0n/JQCVMtm2JO+U57T4vV65CP8s2HsCq1dZBFsh
r3CdkSm9NBQYvspJSvQsxSlHm6ik4i5jDvlehGc9COCPpvm2nYKTbVtUjgjX1eg7
WfjqtMJJxzvsGh4l62BwcEcCgYEAlO9Zrloiy9TmOBvFntvkgo0suRF9ajqeAmZw
GKikBb2uywZSN504gzWcStlKX8J/c+UhcCkGaCUeSfU99apJQsrMAom8QxK+evqJ
k0FuNHwBEhBKx3wGrbojgHUZJIvlms7BLRVDroaTE6O30VC/MnM9IJV0BH+OQdF6
SbLIkVkCgYEAhOzyCrTAv7z1nuNF4MyfL2mSkT57NcqtddKVU7VODqdazGbrCdJT
hodtxyFPY5RkLD5p+lHXBQ4ZnBsKhEVCC9Sjy8LYpb3OKptltNsnNZBMLstEjFL5
q4cWafw+y1xJUQxkIDatLWNne7Tgh7BL91TCBX1r+qp6Bj4nPo61mn0=
-----END RSA PRIVATE KEY-----
`)

var cert_pem = []byte(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`)
