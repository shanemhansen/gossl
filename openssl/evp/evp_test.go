package evp

import "testing"
func TestIt(t *testing.T) {
    OpenSSLAddAllCiphers()
    ciphers_to_test := []string{"bf-ecb", "aes-128-ecb"}
    for index := range ciphers_to_test {
        cipher := ciphers_to_test[index]
        ctx := NewCipherCtx()
        e := ctx.EncryptInit(CipherByName(cipher), make([]byte, 16), make([]byte, 8))
        if e != nil {
            t.Fatal("Cipher is required")
        }
        out := make([]byte, 16*2) //we have to overallocate I guess
        in := []byte("my name is shane")
        n, err := ctx.EncryptUpdate(out, in)
        if err != nil {
            t.Fatal("error encrypting", err)
        }
        tmplength, err := ctx.EncryptFinal(out[n:])
        if err != nil {
            t.Fatal("error encrypting", err)
        }
        out = out[:n+tmplength]
        ctx.DecryptInit(CipherByName(cipher), make([]byte, 16), make([]byte, 8))
        in = out
        out = make([]byte, 16*2)
        n1, err := ctx.DecryptUpdate(out, in)
        if err != nil {
            t.Fatal("error encrypting", err)
        }
        n, err = ctx.DecryptFinal(out[:n1])
        out = out[:(n1 + n)]
        if err != nil {
            t.Fatal("error encrypting", err)
        }
        if string(out) != "my name is shane" {
            t.Fatal("problem decrypting")
        }
    }
}
