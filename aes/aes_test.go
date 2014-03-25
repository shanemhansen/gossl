package aes

import "bytes"
import "testing"

//Test a known key and known data to ensure they
//encrypt and decrypt properly. Verify encrypted value
//against value we've calculated via openssl enc and crypto/aes
func TestAES128(t *testing.T) {
	key := []byte("1234567890123456")
	src := key
	dst := make([]byte, len(key))
	cipher, err := NewCipher(key)
	if err != nil {
		panic(err)
	}
	cipher.Encrypt(dst, src)
	cipher, err = NewCipher(key)
	if err != nil {
		panic(err)
	}
	cleartext := make([]byte, len(src))
	cipher.Decrypt(cleartext, dst)
	known_value := []byte{117, 124, 205, 12,
		220, 92, 144, 234,
		219, 238, 236, 246,
		56, 221, 0, 0}
	if bytes.Compare(dst, known_value) != 0 {
		t.Fatal("encryption failed")
	}
	if bytes.Compare(cleartext, src) != 0 {
		t.Fatal("couldn't decrypt")
	}
}
func TestAES256(t *testing.T) {
	key := []byte("12345678901234561234567890123456")
	src := []byte("1234567890123456")
	dst := make([]byte, len(src))
	cipher, err := NewCipher(key)
	if err != nil {
		panic(err)
	}
	cipher.Encrypt(dst, src)
	cleartext := make([]byte, len(src))
	cipher.Decrypt(cleartext, dst)
	if bytes.Compare(cleartext, src) != 0 {
		t.Fatal("couldn't decrypt")
	}

}
func TestAES192(t *testing.T) {
	key := []byte("123456789012345612345678")
	src := []byte("1234567890123456")
	dst := make([]byte, len(src))
	cipher, err := NewCipher(key)
	if err != nil {
		panic(err)
	}
	cipher.Encrypt(dst, src)
	cleartext := make([]byte, len(src))
	cipher.Decrypt(cleartext, dst)
	if bytes.Compare(cleartext, src) != 0 {
		t.Fatal("couldn't decrypt")
	}

}
func TestAESError(t *testing.T) {
	key := []byte("1234567")
	_, err := NewCipher(key)
	if err == nil {
		t.Fatal("expected error")
	}
}
