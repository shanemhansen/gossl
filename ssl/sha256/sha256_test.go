package sha256

import "fmt"
import "testing"

func TestSHA256(t *testing.T) {
    //some simple tests
    //test the empty string
    h := New()
    h.Write([]byte(""))
    if fmt.Sprintf("%x",h.Sum(nil)) != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
        t.Fatal("hash mismatch for empty string")
    }
    h = New()
    h.Write([]byte("foo\n"))
    if fmt.Sprintf("%x",h.Sum(nil)) != "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c" {
        t.Fatal("hash mismatch")
    }
}
