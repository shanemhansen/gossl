package engines

import (
	"testing"

	"github.com/shanemhansen/gossl/nid"
)

//These tests depend on your hardware and kernel.
func TestStructuralEngines(t *testing.T) {
	LoadBuiltinEngines()
	for e := NewFirst(); e != nil; e = e.GetNext() {
		t.Log(e)
	}
}
func TestFunctionalEngines(t *testing.T) {
	LoadBuiltinEngines()
	var e *Engine
	e = NewFunctionalDefaultRSA()
	t.Log(e)
	e = NewFunctionalByCipherEngine(nid.NID_aes_128_cbc)
	t.Log(e)
	e = NewFunctionalByCipherEngine(nid.NID_sha256)
	t.Log(e)
}
