package main

import "fmt"
import "ssl"
import "flag"

func main() {
    h := ssl.NewSHA256Hash()
    flag.Parse()
    h.Write([]byte(flag.Args()[0]))
    fmt.Printf("%x\n", h.Sum(nil))
}
