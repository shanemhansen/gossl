package sha256

import "fmt"
import "testing"

func TestSHA224(t *testing.T) {
    //some simple tests
    //test the empty string
    h := New224()
    h.Write([]byte(""))
    if fmt.Sprintf("%x", h.Sum(nil)) != "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f" {
        t.Fatal("hash mismatch for empty string")
    }
    h = New224()
    h.Write([]byte("foo\n"))
    if fmt.Sprintf("%x",h.Sum(nil)) != "e7d5e36e8d470c3e5103fedd2e4f2aa5c30ab27f6629bdc3286f9dd2" {
        t.Fatal("hash mismatch")
    }
}
