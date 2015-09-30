package sslerr

import (
	"testing"
)

func TestNone(t *testing.T) {
	err := formatError("")
	if err != nil {
		t.Errorf("expected nil, but got %s", err)
	}
	msg := getErrorString(0)
	if msg != "" {
		t.Errorf("expected [], but got [%s]", msg)
	}

	str := SSLErrorMessage().String()
	if str != "" {
		t.Errorf("expected [], but got [%s]", str)
	}
}
