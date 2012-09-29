package err
/*
#include "openssl/ssl.h"
#include "openssl/err.h"
#cgo pkg-config: openssl

*/
import "C"

func SSLErrorMessage() string {
    msg := ""
    var err_code C.ulong
    var flags C.int
    var data *C.char
    for {
        
        err_code = C.ERR_get_error_line_data(nil, nil, &data, &flags)
        if err_code == 0 {
            break
        }
        msg += C.GoString(C.ERR_lib_error_string(err_code))+"\n"   
        msg += C.GoString(C.ERR_func_error_string(err_code))+"\n"   
        msg += C.GoString(C.ERR_reason_error_string(err_code))+"\n"
        if flags&C.ERR_TXT_STRING != 0{
            msg += C.GoString(data)+"\n"
        }
        if flags&C.ERR_TXT_MALLOCED != 0{
//            C.CRYPTO_free(unsafe.Pointer(data))
        } else {
            //regular free.
//            C.free(unsafe.Pointer(data))
        }
    }
    return msg
}
