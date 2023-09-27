package crlloader

import (
	"github.com/gr33nbl00d/caddy-revocation-validator/core/testutils"
	"testing"

	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// Define a test suite
type CRLLoaderSuite struct {
	suite.Suite
	logObserver testutils.LogObserver
	factory     DefaultCRLLoaderFactory
}

func (suite *CRLLoaderSuite) SetupTest() {
	// Initialize the logger and factory before each test
	suite.logObserver = testutils.CreateAllLevelLogObserver()
	suite.factory = DefaultCRLLoaderFactory{}
}

func (suite *CRLLoaderSuite) TestURLLoader() {
	crlLocations := &core.CRLLocations{
		CRLUrl: "http://example.com/crl",
	}

	loader, err := suite.factory.CreatePreferredCrlLoader(crlLocations, suite.logObserver.Logger)

	// Use assert to check for errors and loader types
	assert.NoError(suite.T(), err, "Expected no error, but got one")
	assert.IsType(suite.T(), URLLoader{}, loader, "Expected URLLoader")
	suite.logObserver.AssertLogSize(suite.T(), 0)
}

func (suite *CRLLoaderSuite) TestFileLoader() {
	crlLocations := &core.CRLLocations{
		CRLFile: "/path/to/crl",
	}

	loader, err := suite.factory.CreatePreferredCrlLoader(crlLocations, suite.logObserver.Logger)

	// Use assert to check for errors and loader types
	assert.NoError(suite.T(), err, "Expected no error, but got one")
	assert.IsType(suite.T(), FileLoader{}, loader, "Expected FileLoader")
	suite.logObserver.AssertLogSize(suite.T(), 0)
}

func (suite *CRLLoaderSuite) TestMultiSchemesCRLLoader() {
	crlLocations := &core.CRLLocations{
		CRLDistributionPoints: []string{"http://example.com/crl1", "http://example.com/crl2"},
	}

	loader, err := suite.factory.CreatePreferredCrlLoader(crlLocations, suite.logObserver.Logger)

	// Use assert to check for errors and loader types
	assert.NoError(suite.T(), err, "Expected no error, but got one")
	assert.IsType(suite.T(), MultiSchemesCRLLoader{}, loader, "Expected MultiSchemesCRLLoader")
	var multiSchemeLoader = loader.(MultiSchemesCRLLoader)
	assert.Equal(suite.T(), 2, len(multiSchemeLoader.Loaders))
	suite.logObserver.AssertLogSize(suite.T(), 0)
}

func (suite *CRLLoaderSuite) TestUnsupportedCDPLocationLogsWarning() {
	crlLocations := &core.CRLLocations{
		CRLDistributionPoints: []string{"abcd://example.com/crl1", "http://example.com/crl2"},
	}

	loader, err := suite.factory.CreatePreferredCrlLoader(crlLocations, suite.logObserver.Logger)

	// Use assert to check for errors and loader types
	assert.NoError(suite.T(), err, "Expected no error, but got one")
	assert.IsType(suite.T(), MultiSchemesCRLLoader{}, loader, "Expected MultiSchemesCRLLoader")
	var multiSchemeLoader = loader.(MultiSchemesCRLLoader)
	assert.Equal(suite.T(), 1, len(multiSchemeLoader.Loaders))
	suite.logObserver.AssertLogSize(suite.T(), 1)
	suite.logObserver.AssertMessageEqual(suite.T(), 0, "unsupported CDP Location Scheme")
}

func (suite *CRLLoaderSuite) TestNoSuitableLoader() {
	crlLocations := &core.CRLLocations{}

	_, err := suite.factory.CreatePreferredCrlLoader(crlLocations, suite.logObserver.Logger)

	// Use assert to check for an error
	assert.Error(suite.T(), err, "Expected an error, but got nil")
}

func TestCRLLoaderSuite(t *testing.T) {
	// Run the test suite
	suite.Run(t, new(CRLLoaderSuite))
}
