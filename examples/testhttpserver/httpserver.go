package main

import "net"
import "fmt"
import "html"
import "flag"
import "github.com/shanemhansen/gossl"
import "net/http"

func main() {
	certpath := flag.String("cert", "", "The path to a PEM certificate")
	keypath := flag.String("key", "", "The path to a PEM key")
	flag.Parse()
	if len(*certpath) == 0 || len(*keypath) == 0 {
		flag.PrintDefaults()
		return
	}
	ctx := gossl.NewContext(gossl.SSLv3Method())
	ctx.SetOptions(gossl.OP_NO_COMPRESSION)
	err := ctx.UsePrivateKeyFile(*keypath, gossl.FILETYPE_PEM)
	if err != nil {
		panic(err)
	}
	ctx.UseCertificateFile(*certpath, gossl.FILETYPE_PEM)
	if err != nil {
		panic(err)
	}
	l, err := net.Listen("tcp", ":8000")
	if err != nil {
		panic(err)
	}
	l, err = gossl.NewListener(l, ctx)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q\n", html.EscapeString(r.URL.Path))
	})
	http.Serve(l, nil)

}
