package engines
import "testing"
import "go-ssl/openssl/nid"
//These tests depend on your hardware and kernel.
func TestStructuralEngines(t *testing.T) {
    LoadBuiltinEngines()
    for e := GetFirst(); e != nil; e = e.GetNext() {
        t.Log(e)
    }
}
func TestFunctionalEngines(t *testing.T) {
    LoadBuiltinEngines()
    var e *ENGINE
    e = GetDefaultRSA()
    t.Log(e)
    e = GetCipherEngine(nid.NID_aes_128_cbc)
    t.Log(e)
    e = GetCipherEngine(nid.NID_sha256)
    t.Log(e)
}
