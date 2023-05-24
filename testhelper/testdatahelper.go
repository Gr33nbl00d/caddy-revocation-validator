package testhelper

import (
	"fmt"
	"path"
	"runtime"
)

func GetTestDataFilePath(fileName string) (resultFilePath string) {
	_, curPath, _, ok := runtime.Caller(0)
	if !ok {
		panic(fmt.Errorf("could not find current working directory"))
	}
	return path.Join(curPath, "../../testdata", fileName)
}
