package evp

import "github.com/shanemhansen/gossl/nid"

//cribbed from evp.h
const (
	PK_RSA   int = 0x0001
	PK_DSA   int = 0x0002
	PK_DH    int = 0x0004
	PK_EC    int = 0x0008
	PKT_SIGN int = 0x0010
	PKT_ENC  int = 0x0020
	PKT_EXCH int = 0x0040
	PKS_RSA  int = 0x0100
	PKS_DSA  int = 0x0200
	PKS_EC   int = 0x0400
	PKT_EXP  int = 0x1000 /* <= 512 bit key */
)

var (
	PKEY_NONE int = nid.NID_undef
	PKEY_RSA  int = nid.NID_rsaEncryption
	PKEY_RSA2 int = nid.NID_rsa
	PKEY_DSA  int = nid.NID_dsa
	PKEY_DSA1 int = nid.NID_dsa_2
	PKEY_DSA2 int = nid.NID_dsaWithSHA
	PKEY_DSA3 int = nid.NID_dsaWithSHA1
	PKEY_DSA4 int = nid.NID_dsaWithSHA1_2
	PKEY_DH   int = nid.NID_dhKeyAgreement
	PKEY_EC   int = nid.NID_X9_62_id_ecPublicKey
	PKEY_HMAC int = nid.NID_hmac
	PKEY_CMAC int = nid.NID_cmac
)

const (
	PKEY_MO_SIGN    = 0x0001
	PKEY_MO_VERIFY  = 0x0002
	PKEY_MO_ENCRYPT = 0x0004
	PKEY_MO_DECRYPT = 0x0008
)
