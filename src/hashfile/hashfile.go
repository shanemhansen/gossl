package main

import "os"
import "io"
import "fmt"
import "ssl"
import "flag"

func main() {
    flag.Parse()
    for _, fname := range flag.Args() {
        h := ssl.NewSHA256Hash()
        buf := make([]byte, 1024*8) //reasonable default blocksize
        file, err := os.Open(fname)
        if err != nil {
            panic(err)
        }
        for {
            bytesread, err := file.Read(buf)
            if err != nil && err != io.EOF {
                panic(err)
            }
            if err == io.EOF {
                break
            }
            h.Write(buf[0:bytesread])
        }
        fmt.Printf("%x %s\n", h.Sum(nil), fname)
    }
}

