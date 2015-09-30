package sslerr

/*
#cgo pkg-config: openssl
#include "openssl/ssl.h"
#include "openssl/conf.h"
#include "openssl/err.h"
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func init() {
	C.ERR_load_ERR_strings()
	C.ERR_load_crypto_strings()
	C.OPENSSL_config(nil)
}

// OpenSSL cleanup and freeing
func Cleanup() {
	C.ERR_free_strings()
}

type SSLError struct {
	msg string
}

func (err SSLError) String() string {
	if len(err.msg) == 0 {
		return ""
	}
	return fmt.Sprintf("%s", err.msg)
}

func SSLErrorMessage() SSLError {
	msg := ""
	for {
		errCode := C.ERR_get_error()
		if errCode == 0 {
			break
		}
		msg += getErrorString(errCode)
	}
	C.ERR_clear_error()
	return SSLError{msg: msg}
}

func getErrorString(code C.ulong) string {
	if code == 0 {
		return ""
	}
	msg := fmt.Sprintf("%s:%s:%s\n",
		C.GoString(C.ERR_lib_error_string(code)),
		C.GoString(C.ERR_func_error_string(code)),
		C.GoString(C.ERR_reason_error_string(code)))
	if len(msg) == 4 { //being lazy here, all the strings were empty
		return ""
	}
	//Check for extra line data
	var file *C.char
	var line C.int
	var data *C.char
	var flags C.int
	if int(C.ERR_get_error_line_data(&file, &line, &data, &flags)) != 0 {
		msg += fmt.Sprintf("%s:%s", C.GoString(file), int(line))
		if flags&C.ERR_TXT_STRING != 0 {
			msg += ":" + C.GoString(data)
		}
		if flags&C.ERR_TXT_MALLOCED != 0 {
			C.CRYPTO_free(unsafe.Pointer(data))
		}
	}
	return msg
}

func Error() error {
	return formatError(SSLErrorMessage().String())
}

func formatError(msg string) error {
	if len(msg) == 0 {
		return nil
	}
	return fmt.Errorf("%s", msg)
}
