package gossl

// #include <openssl/ssl.h>
import "C"

type VerifyMode int

const (
	VERIFY_NONE                 VerifyMode = C.SSL_VERIFY_NONE
	VERIFY_PEER                 VerifyMode = C.SSL_VERIFY_PEER
	VERIFY_FAIL_IF_NO_PEER_CERT VerifyMode = C.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
	VERIFY_CLIENT_ONCE          VerifyMode = C.SSL_VERIFY_CLIENT_ONCE
)
