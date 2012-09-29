package evp

import "github.com/shanemhansen/go-ssl/openssl/nid"

//cribbed from evp.h
var PK_RSA int = 0x0001
var PK_DSA int = 0x0002
var PK_DH int = 0x0004
var PK_EC int = 0x0008
var PKT_SIGN int = 0x0010
var PKT_ENC int = 0x0020
var PKT_EXCH int = 0x0040
var PKS_RSA int = 0x0100
var PKS_DSA int = 0x0200
var PKS_EC int = 0x0400
var PKT_EXP int = 0x1000 /* <= 512 bit key */

var PKEY_NONE int = nid.NID_undef
var PKEY_RSA int = nid.NID_rsaEncryption
var PKEY_RSA2 int = nid.NID_rsa
var PKEY_DSA int = nid.NID_dsa
var PKEY_DSA1 int = nid.NID_dsa_2
var PKEY_DSA2 int = nid.NID_dsaWithSHA
var PKEY_DSA3 int = nid.NID_dsaWithSHA1
var PKEY_DSA4 int = nid.NID_dsaWithSHA1_2
var PKEY_DH int = nid.NID_dhKeyAgreement
var PKEY_EC int = nid.NID_X9_62_id_ecPublicKey
var PKEY_HMAC int = nid.NID_hmac
var PKEY_CMAC int = nid.NID_cmac

var PKEY_MO_SIGN = 0x0001
var PKEY_MO_VERIFY = 0x0002
var PKEY_MO_ENCRYPT = 0x0004
var PKEY_MO_DECRYPT = 0x0008
