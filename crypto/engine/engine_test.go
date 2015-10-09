package engine

import (
	"testing"
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
	// NID_aes_128_cbc 419
	e = NewFunctionalByCipherEngine(419)
	t.Log(e)
	// NID_sha256 672
	e = NewFunctionalByCipherEngine(672)
	t.Log(e)
}
