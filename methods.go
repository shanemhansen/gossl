package gossl

/*
#cgo pkg-config: openssl
#include "openssl/ssl.h"
*/
import "C"

//A set of functions for generating OpenSSL methods
type METHOD struct {
	method *C.SSL_METHOD
}

// SSLv3 method
func SSLv3Method() *METHOD {
	return &METHOD{C.SSLv3_method()}
}
func SSLv3ClientMethod() *METHOD {
	return &METHOD{C.SSLv3_client_method()}
}
func SSLv3ServerMethod() *METHOD {
	return &METHOD{C.SSLv3_server_method()}
}

// SSLv3 with fallback to v
func SSLv23Method() *METHOD {
	return &METHOD{C.SSLv23_method()}
}
func SSLv23ClientMethod() *METHOD {
	return &METHOD{C.SSLv23_client_method()}
}
func SSLv23ServerMethod() *METHOD {
	return &METHOD{C.SSLv23_server_method()}
}

// TLSv1.0
func TLSv1Method() *METHOD {
	return &METHOD{C.TLSv1_method()}
}
func TLSv1ClientMethod() *METHOD {
	return &METHOD{C.TLSv1_client_method()}
}
func TLSv1ServerMethod() *METHOD {
	return &METHOD{C.TLSv1_server_method()}
}

// TLSv1.1
func TLSv1_1Method() *METHOD {
	return &METHOD{C.TLSv1_1_method()}
}
func TLSv1_1ClientMethod() *METHOD {
	return &METHOD{C.TLSv1_1_client_method()}
}
func TLSv1_1ServerMethod() *METHOD {
	return &METHOD{C.TLSv1_1_server_method()}
}

// TLSv1.2
func TLSv1_2Method() *METHOD {
	return &METHOD{C.TLSv1_2_method()}
}
func TLSv1_2ClientMethod() *METHOD {
	return &METHOD{C.TLSv1_2_client_method()}
}
func TLSv1_2ServerMethod() *METHOD {
	return &METHOD{C.TLSv1_2_server_method()}
}

// DTLSv1, or TLS over Datagram (UDP)
func DTLSv1Method() *METHOD {
	return &METHOD{C.DTLSv1_method()}
}
func DTLSv1ClientMethod() *METHOD {
	return &METHOD{C.DTLSv1_client_method()}
}
func DTLSv1ServerMethod() *METHOD {
	return &METHOD{C.DTLSv1_server_method()}
}
