package elliptic

import (
	"math/big"
	"testing"
)

func TestP256(t *testing.T) {
	_ = P256()
}

func TestGenerateKey(t *testing.T) {
	_, _, _, err := GenerateKey(P256(), nil)
	if err != nil {
		t.Error("something went wrong generating the key: " + err.Error())
	}
}

func TestMarshal(t *testing.T) {
	b := Marshal(P256(), new(big.Int), new(big.Int))
	t.Log(b)
}

func TestUnmarshal(t *testing.T) {
	b := Marshal(P256(), new(big.Int), new(big.Int))
	t.Log(b)
	x, y := Unmarshal(P256(), b)
	t.Log(x)
	t.Log(y)
}
