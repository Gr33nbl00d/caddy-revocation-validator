package testhelper

import (
	"fmt"
	"github.com/smallstep/assert"
	"path"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGetTestDataFilePath(t *testing.T) {
	result := GetTestDataFilePath("crl1")
	_, curPath, _, ok := runtime.Caller(0)
	if !ok {
		panic(fmt.Errorf("could not find current working directory"))
	}
	curPath = path.Join(curPath, "../../")
	resultRelative, err := filepath.Rel(curPath, result)
	assert.Nil(t, err)
	resultRelative = filepath.ToSlash(resultRelative)
	assert.Equals(t, "testdata/crl1", resultRelative)
}
