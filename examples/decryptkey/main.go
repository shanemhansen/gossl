package main

import "fmt"
import "flag"
import "github.com/shanemhansen/gossl/evp"
import "io/ioutil"

func main() {
	keypath := flag.String("key", "", "The path to a PEM key")
	flag.Parse()
	if len(*keypath) == 0 {
		flag.PrintDefaults()
		return
	}
	buf, err := ioutil.ReadFile(*keypath)
	if err != nil {
		panic(err)
	}
	key, err := evp.LoadPrivateKeyPEM(buf)
	if err != nil {
		panic(err)
	}
	buf, err = key.DumpPEM()
	if err != nil {
		panic(err)
	}

	fmt.Printf("%s", buf)
}
