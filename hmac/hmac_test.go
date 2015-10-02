package hmac

import (
	"testing"

	"github.com/shanemhansen/gossl/engine"
	"github.com/shanemhansen/gossl/sha256"
	"github.com/shanemhansen/gossl/sslerr"
)

func TestHMACNewWithEngine(t *testing.T) {
	engine.LoadBuiltinEngines()

	// NID_hmac_sha1 781
	eng := engine.NewFunctionalByDigestEngine(781)
	hmacWithEngine := NewWithEngine(eng, sha256.New, nil)

	if hmacWithEngine == nil {
		t.Errorf("Something went wrong initializing an hmac with an engine %v", sslerr.Error())
	}
}
