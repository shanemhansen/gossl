package http

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Transport
type Transport struct {
	defaultTransport http.RoundTripper
}

// RoundTrip
func (t Transport) RoundTrip(req *http.Request) (*http.Response, error) {
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
		if t.defaultTransport == nil {
			return http.DefaultTransport.RoundTrip(req)
		}
		return t.defaultTransport.RoundTrip(req)
	}
	if req.URL.Host == "" {
		req.Body.Close()
		return nil, errors.New("http: no Host in request URL")
	}

	// TODO(runcom): decorate ctx with options from New maybe
	//ctx, err := openssl.NewCtx()
	//if err != nil {
	//return nil, err
	//}

	//// TODO(runcom):
	//// maybe need a cert pool varying from system to system?
	//if err := ctx.LoadVerifyLocations("", "/etc/ssl/certs/"); err != nil {
	//return nil, err
	//}

	//targetAddr := canonicalAddr(req.URL)
	//conn, err := openssl.Dial("tcp", targetAddr, ctx, 0)
	//if err != nil {
	//return nil, err
	//}

	//reader := bufio.NewReader(conn)
	//writer := bufio.NewWriter(conn)
	//readDone := make(chan responseAndError, 1)
	//writeDone := make(chan error, 1)

	//// Always request GZIP.
	//req.Header.Set("Accept-Encoding", "gzip")

	//// Write the request.
	//go func() {
	//err := req.Write(writer)
	//if err == nil {
	//writer.Flush()
	//}
	//writeDone <- err
	//}()

	//// And read the response.
	//go func() {
	//resp, err := http.ReadResponse(reader, req)
	//if err != nil {
	//readDone <- responseAndError{nil, err}
	//return
	//}

	//resp.Body = &connCloser{resp.Body, conn}

	//if resp.Header.Get("Content-Encoding") == "gzip" {
	//resp.Header.Del("Content-Encoding")
	//resp.Header.Del("Content-Length")
	//resp.ContentLength = -1

	//reader, err := gzip.NewReader(resp.Body)
	//if err != nil {
	//resp.Body.Close()
	//readDone <- responseAndError{nil, err}
	//return
	//}
	//resp.Body = &readerAndCloser{reader, resp.Body}
	//}

	//readDone <- responseAndError{resp, nil}
	//}()

	//if err = <-writeDone; err != nil {
	//return nil, err
	//}

	//r := <-readDone

	//if r.err != nil {
	//return nil, r.err
	//}

	//return r.res, nil
	return nil, nil
}

// NewTransport
func NewTransport(defaultTransport http.RoundTripper) http.RoundTripper {
	if defaultTransport == nil {
		defaultTransport = http.DefaultTransport
	}
	return &Transport{defaultTransport: defaultTransport}
}

func canonicalAddr(url *url.URL) string {
	addr := url.Host

	if !hasPort(addr) {
		return addr + ":443"
	}

	return addr
}

func hasPort(s string) bool {
	return strings.LastIndex(s, ":") > strings.LastIndex(s, "]")
}

type connCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (cc *connCloser) Close() error {
	cc.conn.Close()
	return cc.ReadCloser.Close()
}

type readerAndCloser struct {
	io.Reader
	io.Closer
}

type responseAndError struct {
	res *http.Response
	err error
}
