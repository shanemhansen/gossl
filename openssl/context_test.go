package openssl

import "testing"

func TestNewContext(t *testing.T) {
    ctx := NewContext(SSLv23Method())
    if ctx == nil {
        t.Fatal("problem creating context")
    }
}