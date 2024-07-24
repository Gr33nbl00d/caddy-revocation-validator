package crlreader

import (
	"bufio"
	"encoding/base64"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/hashing"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/pemreader"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"github.com/stretchr/testify/suite"
	"os"
	"testing"
)

type HashingCRLReaderFactoryTestSuite struct {
	suite.Suite
	factory HashingCRLReaderFactory
}

func (suite *HashingCRLReaderFactoryTestSuite) SetupTest() {
	suite.factory = HashingCRLReaderFactory{}
}

func (suite *HashingCRLReaderFactoryTestSuite) TestNewHashingCRLReaderWithPemFile() {
	crlFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.pem"))
	suite.Require().NoError(err)
	defer crlFile.Close()

	// Use the factory to create the reader
	crlReader := suite.factory.newHashingCRLReader(crlFile)

	// Create the expected reader using the actual PEM reader logic
	pemReader := pemreader.NewPemReader(bufio.NewReader(crlFile))
	decoder := base64.NewDecoder(base64.StdEncoding, &pemReader)
	expectedReader := bufio.NewReader(decoder)

	// Ensure the reader is created correctly
	suite.IsType(hashing.HashingReaderWrapper{}, crlReader)
	suite.Equal(expectedReader, crlReader.Reader)
}

func (suite *HashingCRLReaderFactoryTestSuite) TestNewHashingCRLReaderWithDerFile() {
	crlFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.crl"))
	suite.Require().NoError(err)
	defer crlFile.Close()

	// Use the factory to create the reader
	crlReader := suite.factory.newHashingCRLReader(crlFile)

	// Create the expected reader using the actual DER reader logic
	expectedReader := bufio.NewReader(crlFile)

	// Ensure the reader is created correctly
	suite.IsType(hashing.HashingReaderWrapper{}, crlReader)
	suite.Equal(expectedReader, crlReader.Reader)
}

func (suite *HashingCRLReaderFactoryTestSuite) TestNewHashingDERCRLReader() {
	crlFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.crl"))
	suite.Require().NoError(err)
	defer crlFile.Close()

	crlReader := suite.factory.newHashingDERCRLReader(crlFile)

	expectedReader := bufio.NewReader(crlFile)
	suite.IsType(hashing.HashingReaderWrapper{}, crlReader)
	suite.Equal(expectedReader, crlReader.Reader)
}

func (suite *HashingCRLReaderFactoryTestSuite) TestNewHashingPEMCRLReader() {
	crlFile, err := os.Open(testhelper.GetTestDataFilePath("crl1.pem"))
	suite.Require().NoError(err)
	defer crlFile.Close()

	pemReader := pemreader.NewPemReader(bufio.NewReader(crlFile))
	decoder := base64.NewDecoder(base64.StdEncoding, &pemReader)

	crlReader := suite.factory.newHashingPEMCRLReader(crlFile)

	expectedReader := bufio.NewReader(decoder)
	suite.IsType(hashing.HashingReaderWrapper{}, crlReader)
	suite.Equal(expectedReader, crlReader.Reader)
}

func TestHashingCRLReaderFactoryTestSuite(t *testing.T) {
	suite.Run(t, new(HashingCRLReaderFactoryTestSuite))
}
