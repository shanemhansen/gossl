package evp

import "testing"

func TestIt(t *testing.T) {
	ciphers_to_test := []string{"bf-ecb", "aes-128-ecb"}
	for index := range ciphers_to_test {
		cipher := ciphers_to_test[index]
		ctx := NewCipherCtx()
		msg := "my name is shane"
		err := ctx.EncryptInit(CipherByName(cipher), make([]byte, len(msg)), make([]byte, 8))
		if err != nil {
			t.Fatalf("Cipher is required: %s", err)
		}
		out := make([]byte, len(msg)*2) //we have to overallocate I guess
		in := []byte(msg)
		n, err := ctx.EncryptUpdate(out, in)
		if err != nil {
			t.Fatal("error encrypting", err)
		}
		tmplength, err := ctx.EncryptFinal(out[n:])
		if err != nil {
			t.Fatal("error encrypting", err)
		}
		out = out[:n+tmplength]
		err = ctx.DecryptInit(CipherByName(cipher), make([]byte, len(msg)), make([]byte, 8))
		if err != nil {
			t.Fatalf("Cipher is required: %s", err)
		}

		in = out
		out = make([]byte, len(msg)*2)
		n1, err := ctx.DecryptUpdate(out, in)
		if err != nil {
			t.Fatal("error encrypting", err)
		}
		n, err = ctx.DecryptFinal(out[:n1])
		out = out[:(n1 + n)]
		if err != nil {
			t.Fatal("error encrypting", err)
		}
		if string(out) != msg {
			t.Errorf("problem decrypting with %q. Expected %q; got %q", cipher, msg, string(out))
		}
	}
}
