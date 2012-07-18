package tls

/*
#cgo pkg-config: openssl
#include "openssl/bio.h"
#include "openssl/err.h"
extern int go_conn_bio_write(BIO* bio, const char* buf, int num);
extern int go_conn_bio_read(BIO* bio, char* buf, int num);
extern int go_conn_bio_new(BIO* bio);
extern int go_conn_bio_free(BIO* bio);
extern long go_conn_bio_ctrl(BIO *b, int cmd, long num, void *ptr);

static BIO_METHOD methods_connp={
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
extern BIO_METHOD* BIO_s_conn(void) {
 return &methods_connp;
}
//lame wrapper around ssl's variadic put error
void go_conn_put_error(const char* p) {
 ERR_add_error_data(1, p);
}
*/
import "C"
