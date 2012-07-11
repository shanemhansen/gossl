package sha1

import "fmt"
import "testing"

func TestSHA1(t *testing.T) {
    //some simple tests
    //test the empty string
    h := New()
    h.Write([]byte(""))
    if fmt.Sprintf("%x",h.Sum(nil)) != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
        t.Fatal("hash mismatch for empty string")
    }
    h = New()
    h.Write([]byte("foo\n"))
    if fmt.Sprintf("%x",h.Sum(nil)) != "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15" {
        t.Fatal("hash mismatch")
    }
}
