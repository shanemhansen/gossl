package http

/*
#cgo pkg-config: openssl

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>

struct ssl_connection_t {
	int socket;
	SSL *ssl_handle;
	SSL_CTX *ssl_context;
};

typedef struct ssl_connection_t SSL_connection;

static int tcp_connect(const char **address, const long *port)
{
	int handle, error;
	struct hostent *host;
	struct sockaddr_in server;

	// TODO(runcom): replace with getaddrinfo(3)
	host = gethostbyname(*address);
	if (host == NULL)
		return 0;

	handle = socket(AF_INET, SOCK_STREAM, 0);
	if (handle == -1)
		return 0;

	server.sin_family = AF_INET;
	server.sin_port = htons(*port);
	server.sin_addr = *((struct in_addr *)host->h_addr);
	bzero(&(server.sin_zero), 8);

	error = connect(handle, (struct sockaddr *)&server,
	sizeof(struct sockaddr));
	if (error == -1)
		return 0;

	return handle;
}

static SSL_connection *ssl_connect(const char *address, const long port)
{
	SSL_connection *conn;

	conn = malloc(sizeof(SSL_connection));
	if (conn == NULL)
		return NULL;

	conn->socket = tcp_connect(&address, &port);
	if (conn->socket == 0)
		goto out_bad;

	SSL_load_error_strings();
	SSL_library_init();

	conn->ssl_context = SSL_CTX_new(SSLv23_client_method());
	if (conn->ssl_context == NULL)
		goto out_bad;

	conn->ssl_handle = SSL_new(conn->ssl_context);
	if (conn->ssl_handle == NULL)
		goto out_bad;

	if (!SSL_set_fd(conn->ssl_handle, conn->socket))
		goto out_bad;

	if (SSL_connect(conn->ssl_handle) != 1)
		goto out_bad;

	return conn;

out_bad:
	free(conn);
	return NULL;
}

static int ssl_write(SSL_connection *conn, char *text)
{
	int res;

	if (conn != NULL)
		res = SSL_write(conn->ssl_handle, text, strlen(text));
		if (res <= 0)
			// The write operation was not successful. Probably the underlying
			// connection was closed. Call SSL_get_error() with the return value
			// ret to find out, whether an error occurred or the connection was
			// shut down cleanly (SSL_ERROR_ZERO_RETURN).
			// TODO(runcom): should differentiate for res == 0 as the man says
			return res;
		return 1;
	return 0;
}

static char *ssl_read(SSL_connection *conn)
{
	const int read_size = 1024;
	char *rc = NULL;
	int received, count = 0;
	char buffer[1024];

	if (conn == NULL)
		return NULL;

	while (1) {
		if (rc == NULL)
			rc = malloc(read_size * sizeof(char) + 1);
		else
			rc = realloc(rc, (count + 1) * read_size * sizeof(char) + 1);

		received = SSL_read(conn->ssl_handle, buffer, read_size);
		if (received <= 0)
			// an error or clean shutdown occurred...
			break;

		buffer[received] = '\0';

		if (received > 0)
			strcat(rc, buffer);

		if (received < read_size)
			break;

		count++;
	}

	return rc;
}

static void ssl_disconnect(SSL_connection *conn)
{
	if (conn->socket)
		close(conn->socket);

	if (conn->ssl_handle) {
		SSL_shutdown(conn->ssl_handle);
		SSL_free(conn->ssl_handle);
	}

	if (conn->ssl_context)
		SSL_CTX_free(conn->ssl_context);

	free(conn);
}

static int c_strlen(char *buf)
{
	return strlen(buf);
}
*/
import "C"
import (
	"errors"
	"net/http"
	"unsafe"
)

// The golang stdlib http.Client uses the http.DefaultTransport by defualt (and
// subsequently http.Get(), etc).
//
// That DefaultTransport uses the stdlib crypto/tls.
// To override usage of the stdlib crypto/tls, just set this OpenSSLRoundTripper
// as the DefaultTransport for your application. Likely in an init() somewhere.
//
//   import "net/http"
//
//   func init() {
//     http.DefaultTransport = &OpenSSLTransport{}
//   }
//
type OpenSSLTransport struct {
	// a default RoundTripper for all non-https schemes
	// ( this defaults to http.DefaultTransport )
	DefaultTransport http.RoundTripper
}

func (t *OpenSSLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		req.Body.Close()
		return nil, errors.New("http: nil Request.URL")
	}
	if req.Header == nil {
		req.Body.Close()
		return nil, errors.New("http: nil Request.Header")
	}
	// short circuit to most use-cases
	if req.URL.Scheme != "https" {
		if t.DefaultTransport != nil {
			return t.DefaultTransport.RoundTrip(req)
		}
		return t.DefaultTransport.RoundTrip(req)
	}
	if req.URL.Host == "" {
		req.Body.Close()
		return nil, errors.New("http: no Host in request URL")
	}

	//treq := &transportRequest{Request: req}

	conn, err := t.getConn(req)
	if err != nil {
		req.Body.Close()
		return nil, err
	}

	_ = conn

	//return pconn.roundTrip(treq)
	return nil, nil
}

type transportRequest struct {
	*http.Request // original request
}

type connection struct {
	conn *C.SSL_connection
}

func (c *connection) Write(data []byte) error {
	if C.ssl_write(c.conn, C.CString(string(data))) != 1 {
		return errors.New("couldn't write to ssl connection")
	}
	return nil
}

func (c *connection) Read() ([]byte, error) {
	read := C.ssl_read(c.conn)
	if read == nil {
		return nil, errors.New("error while reading from ssl connection")
	}
	return C.GoBytes(unsafe.Pointer(read), C.c_strlen(read)), nil
}

func (c *connection) Close() {
	C.ssl_disconnect(c.conn)
}

func (t *OpenSSLTransport) getConn(req *http.Request) (*connection, error) {
	addr := C.CString(req.URL.Host)
	defer C.free(unsafe.Pointer(addr))
	conn := C.ssl_connect(addr, 443)
	if conn == nil {
		return nil, errors.New("couldn't connect")
	}
	return &connection{conn: conn}, nil
}
