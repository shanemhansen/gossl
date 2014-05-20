package sslerr

/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl

*/
import "C"
import "fmt"
import "unsafe"

var sslFmtString = "%s:%s:%s\n"

type errCode C.ulong

func SSLErrorMessage() string {
	msg := ""
	for {
		err_code := C.ERR_get_error()
		if err_code == 0 {
			break
		}
		msg += get_error_string(errCode(err_code))
	}
	return msg
}

func get_error_string(code errCode) string {
	err_code := C.ulong(code)
	if err_code == 0 {
		return ""
	}
	msg := fmt.Sprintf(sslFmtString,
		C.GoString(C.ERR_lib_error_string(err_code)),
		C.GoString(C.ERR_func_error_string(err_code)),
		C.GoString(C.ERR_reason_error_string(err_code)))
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
	return formatError(SSLErrorMessage())
}

func formatError(msg string) error {
	if len(msg) == 0 {
		return nil
	}
	return fmt.Errorf("%s", msg)
}
