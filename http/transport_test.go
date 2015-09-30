package http

import (
	"bytes"
	"net/http"
	"testing"
)

func TestRoundTripperWithoutURL(t *testing.T) {
	tr := OpenSSLTransport{}
	req, err := http.NewRequest("GET", "", bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	req.URL = nil
	_, err = tr.RoundTrip(req)
	expected := "http: nil Request.URL"
	if err.Error() != expected {
		t.Fatalf("Expected %q, got %q", expected, err.Error())
	}
}

func TestGetConn(t *testing.T) {
	tr := OpenSSLTransport{}
	req, err := http.NewRequest("GET", "https://google.com", bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	c, err := tr.getConn(req)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestGetConnFail(t *testing.T) {
	tr := OpenSSLTransport{}
	req, err := http.NewRequest("GET", "https://notfoundwtf.com", bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	c, err := tr.getConn(req)
	if err == nil {
		c.Close()
		t.Fatalf("Expected err, got nil instead")
	}
}

func TestGetConnWriteRead(t *testing.T) {
	tr := OpenSSLTransport{}
	req, err := http.NewRequest("GET", "https://google.com", bytes.NewBuffer(nil))
	if err != nil {
		t.Fatal(err)
	}
	c, err := tr.getConn(req)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Write(bytes.NewBufferString("GET /\r\n\r\n").Bytes()); err != nil {
		t.Fatal(err)
	}
	b, err := c.Read()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(b))
}
