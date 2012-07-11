package main

import "fmt"
import "ssl/sha256"
import "flag"

func main() {
    h := sha256.New()
    flag.Parse()
    h.Write([]byte(flag.Args()[0]))
    fmt.Printf("%x\n", h.Sum(nil))
}
