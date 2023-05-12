package hashing

import (
	"github.com/smallstep/assert"
	"testing"
)

func TestSum64(t *testing.T) {
	result := Sum64("helloworld")
	expectedResult := []byte{129, 85, 74, 146, 94, 49, 217, 16}
	assert.Equals(t, expectedResult, result, "fnva hash result does not match")
}
