package gossl

import (
	"bytes"
	"testing"
)

func TestMemoryBIO(t *testing.T) {
	bio := NewBIO(BIOSMem())
	msg := []byte("Hello, world")
	n := bio.Write(msg)
	if n != len(msg) {
		t.Fatalf("Expected write length %d, got %d", len(msg), n)
	}
	data := bio.GetBytes()
	if bytes.Compare(msg, data) != 0 {
		t.Fatalf("Expected %s, got %s", string(msg), string(data))
	}
}
