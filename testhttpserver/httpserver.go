package main

import "net"
import "fmt"
import "html"
import "flag"
import "go-ssl/tls"
import "net/http"
import cryptotls "crypto/tls"

func main() {
    config := new(cryptotls.Config)
    certpath := flag.String("cert", "", "The path to a PEM certificate")
    keypath := flag.String("key", "", "The path to a PEM key")
    flag.Parse()
    if len(*certpath) == 0 || len(*keypath) == 0 {
        flag.PrintDefaults()
        return
    }
    cert, err := cryptotls.LoadX509KeyPair(*certpath, *keypath)
    if err != nil {
        panic(err)
    }
    certs := []cryptotls.Certificate{cert}
    config.Certificates = certs
    l, err := net.Listen("tcp", ":8000")
    l, err = tls.NewListener(l, config)
    if err != nil {
        panic(err)
    }
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, "Hello, %q\n", html.EscapeString(r.URL.Path))
    })
    http.Serve(l, nil)
}
