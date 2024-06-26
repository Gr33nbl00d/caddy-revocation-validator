package pemreader

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"github.com/smallstep/assert"
	assert2 "github.com/stretchr/testify/assert"
	"io"
	"os"
	"strings"
	"testing"
)

func TestIsPemFileWithPemFile(t *testing.T) {
	crlFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.pem"))
	defer utils.CloseWithErrorHandling(crlFile.Close)
	if err != nil {
		t.Errorf("error occured %v", err)
	}
	err, isPemFile := IsPemFile(crlFile)
	assert.Nil(t, err)
	assert.True(t, isPemFile)
}

func TestIsPemFileWithNonePemFile(t *testing.T) {
	crlFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.crl"))
	defer utils.CloseWithErrorHandling(crlFile.Close)
	if err != nil {
		t.Errorf("error occured %v", err)
	}
	err, isPemFile := IsPemFile(crlFile)
	assert.Nil(t, err)
	assert.False(t, isPemFile)
}

func TestNewPemReader(t *testing.T) {
	testReader := bufio.NewReader(strings.NewReader("  some funky shiny bytes"))
	result := NewPemReader(testReader)
	assert.NotNil(t, result)
	assert2.Same(t, testReader, result.Reader)
}

func TestPemReader_Read(t *testing.T) {
	testFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.pem"))
	assert.Nil(t, err)
	reader := NewPemReader(bufio.NewReader(testFile))
	allBytes, err := readAllBytes(t, reader)
	assert.Nil(t, err)
	hasher := sha1.New()

	hasher.Write(allBytes)
	resultHash := hex.EncodeToString(hasher.Sum(nil))
	assert.Equals(t, "13e491524e70a5b1057b9010fe7b5aa3fc8b60b6", resultHash)
}

func TestPemReader_ReadPemWithPadding(t *testing.T) {
	testFile, err := os.Open(testhelper.GetTestDataFilePath("crlpadding.pem"))
	assert.Nil(t, err)
	reader := NewPemReader(bufio.NewReader(testFile))
	allBytes, err := readAllBytes(t, reader)
	assert.Nil(t, err)
	hasher := sha1.New()

	hasher.Write(allBytes)
	resultHash := hex.EncodeToString(hasher.Sum(nil))
	assert.Equals(t, "1a0526838635309c0c7660d04372f66d1d54a1dd", resultHash)
}

func TestPemReader_ReadWithInvalidFile(t *testing.T) {
	testFile, err := os.Open(testhelper.GetTestDataFilePath("invalidcrl1.pem"))
	assert.Nil(t, err)
	reader := NewPemReader(bufio.NewReader(testFile))
	_, err = readAllBytes(nil, reader)
	assert.Error(t, err)
}

func TestPemReader_ReadWithInvalidBuffer(t *testing.T) {
	testFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.pem"))
	assert.Nil(t, err)
	reader := NewPemReader(bufio.NewReader(testFile))
	var readBuffer = make([]byte, 10)
	_, err = reader.Read(readBuffer)
	assert.Error(t, err)
}

func readAllBytes(t *testing.T, reader PemReader) (readData []byte, err error) {
	buf := &bytes.Buffer{}
	for {
		var readBuffer = make([]byte, 66)
		read, err := reader.Read(readBuffer)
		if err == io.EOF {
			err = nil
			allBytes := buf.Bytes()
			return allBytes, nil
		}
		if err != nil {
			return nil, err
		}
		t.Logf("Read bytes: %s", hex.EncodeToString(readBuffer[0:read]))
		buf.Write(readBuffer[0:read])
	}
}
