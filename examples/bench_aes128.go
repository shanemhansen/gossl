package main

import "fmt"
import "time"
import "crypto/cipher"
import "crypto/aes"
import sslAES "go-ssl/aes"

func bench(h *cipher.Block, msg string) {
    bufsize := 102400
    iterations := 10000
    src := make([]byte, bufsize)
    dst := make([]byte, bufsize)
    t := time.Now()
    for i:=0; i< iterations; i++ {
        (*h).Encrypt(src, dst)
        (*h).Encrypt(dst, src)
    }
    fmt.Printf("%s took %s to process %d mb\n", msg, time.Since(t), bufsize*iterations/1024/1024)

}
func main() {
    fmt.Println("This program benchmarks crypto/aes and aes/aes implementations")
    k := []byte("1234567890123456")
    h, _ := aes.NewCipher(k)
    bench(&h, "crypto/aes")
    ssl, _ := sslAES.NewCipher(k)
    bench(&ssl, "ssl/aes")
}
