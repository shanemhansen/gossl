package main

import "fmt"
import "time"
import "hash"
import "crypto/rand"
import "crypto/sha256"
import sslSha256 "github.com/shanemhansen/go-ssl/sha256"

func bench_sha256(h *hash.Hash, msg string) {
    bufsize := 10240
    iterations := 10000
    buf := make([]byte, bufsize)
    n, err := rand.Read(buf)
    t := time.Now()
    for i := 0; i < iterations; i++ {
        if err != nil {
            panic("problem reading random data")
        }
        (*h).Write(buf[0:n])
    }
    fmt.Printf("%s took %s to process %d mb\n", msg, time.Since(t), bufsize*iterations/1024/1024)

}
func main() {
    fmt.Println("This program benchmarks crypto/sha256 and aes/sha256 implementations")
    h := sha256.New()
    bench_sha256(&h, "crypto/sha256")
    ssl := sslSha256.New()
    bench_sha256(&ssl, "ssl/aes")
}
