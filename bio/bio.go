package bio

/*
#cgo pkg-config: openssl
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

extern BIO_METHOD *BIO_s_conn(void);
extern int go_conn_bio_write(BIO *bio, const char *buf, int num);
extern int go_conn_bio_read(BIO *bio, char *buf, int num);
extern int go_conn_bio_new(BIO *bio);
extern int go_conn_bio_free(BIO *bio);
extern long go_conn_bio_ctrl(BIO *bio, int cmd, long num, void *ptr);

static BIO_METHOD methods_connp = {
	BIO_TYPE_SOURCE_SINK,
	"go net.Conn",
	go_conn_bio_write,
	go_conn_bio_read,
	NULL,
	NULL,
	go_conn_bio_ctrl,
	go_conn_bio_new,
	go_conn_bio_free
};

extern BIO_METHOD *BIO_s_conn(void)
{
	return &methods_connp;
}

void go_conn_put_error(const char *p)
{
	ERR_add_error_data(1, p);
}

void clear_sys_error(void)
{
	errno = 0;
}

void set_errno(int e)
{
	errno = e;
}

int get_errno(void)
{
	return errno;
}
*/
import "C"
import "unsafe"

type BIO struct {
	BIO  *C.BIO
	conn *Conn
}

func NewBIO(method *BIOMethod) *BIO {
	return newBIO(C.BIO_new(method.BIOMethod))
}

func newBIO(bio *C.BIO) *BIO {
	b := &BIO{BIO: bio}
	return b

}

//Thin wrappers over OpenSSL bio.
//See BIO_read documentation for return value negative means error
//error message is gotten be calling ssl.getError()
func (self *BIO) Read(b []byte) int {
	C.clear_sys_error()
	ret := int(C.BIO_read(self.BIO, unsafe.Pointer(&b[0]), C.int(len(b))))
	return ret
}

//See BIO_write
func (self *BIO) Write(b []byte) int {
	C.clear_sys_error()
	ret := int(C.BIO_write(self.BIO, unsafe.Pointer(&b[0]), C.int(len(b))))
	return ret
}

func (self *BIO) SetAppData(conn *Conn) {
	self.BIO.ptr = unsafe.Pointer(conn)
}

func (self *BIO) GetAppData() *Conn {
	return (*Conn)(self.BIO.ptr)
}

func (self *BIO) Ctrl(cmd int, larg int, data unsafe.Pointer) int {
	return int(C.BIO_ctrl(self.BIO, C.int(cmd), C.long(larg), data))
}

func (self *BIO) GetBytes() []byte {
	var temp *C.char
	buf_len := self.Ctrl(int(C.BIO_CTRL_INFO), 0, unsafe.Pointer(&temp))
	return C.GoBytes(unsafe.Pointer(temp), C.int(buf_len))
}

type BIOMethod struct {
	BIOMethod *C.BIO_METHOD
}

func newBIOMethod(method *C.BIO_METHOD) *BIOMethod {
	return &BIOMethod{method}
}

func BIOConn() *BIOMethod {
	return newBIOMethod(C.BIO_s_conn())
}

func BIOSMem() *BIOMethod {
	return newBIOMethod(C.BIO_s_mem())
}
