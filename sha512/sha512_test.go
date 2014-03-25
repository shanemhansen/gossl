package sha512

import "fmt"
import "testing"

func TestSHA512(t *testing.T) {
	//some simple tests
	//test the empty string
	h := New()
	h.Write([]byte(""))
	if fmt.Sprintf("%x", h.Sum(nil)) != "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" {
		t.Fatal("hash mismatch for empty string")
	}
	h = New()
	h.Write([]byte("foo\n"))
	if fmt.Sprintf("%x", h.Sum(nil)) != "0cf9180a764aba863a67b6d72f0918bc131c6772642cb2dce5a34f0a702f9470ddc2bf125c12198b1995c233c34b4afd346c54a2334c350a948a51b6e8b4e6b6" {
		t.Fatal("hash mismatch")
	}
}
func TestSHA384(t *testing.T) {
	//some simple tests
	//test the empty string
	h := New384()
	h.Write([]byte(""))
	if fmt.Sprintf("%x", h.Sum(nil)) != "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b" {
		t.Fatal("hash mismatch for empty string")
	}
	h = New384()
	h.Write([]byte("foo\n"))
	if fmt.Sprintf("%x", h.Sum(nil)) != "8effdabfe14416214a250f935505250bd991f106065d899db6e19bdc8bf648f3ac0f1935c4f65fe8f798289b1a0d1e06" {
		t.Fatal("hash mismatch")
	}
}
