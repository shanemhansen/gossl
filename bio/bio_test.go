package bio

import (
	"bytes"
	"testing"
)

func TestMemoryBIO(t *testing.T) {
	bio := NewBIO(BIOSMem())
	msg := []byte("Hello, world")
	n := bio.Write(msg)
	if n != len(msg) {
		t.Fatal("wtf")
	}
	data := bio.GetBytes()
	if bytes.Compare(msg, data) != 0 {
		t.Fatal("wtf")
	}
}
