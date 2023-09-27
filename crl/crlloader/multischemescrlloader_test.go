package crlloader

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

// MockCRLLoader is a mock implementation of the CRLLoader interface
type MockCRLLoader struct {
	mock.Mock
}

func (m *MockCRLLoader) LoadCRL(filePath string) error {
	args := m.Called(filePath)
	return args.Error(0)
}

func (m *MockCRLLoader) GetCRLLocationIdentifier() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}

func (m *MockCRLLoader) GetDescription() string {
	args := m.Called()
	return args.String(0)
}

type MultiSchemesCRLLoaderSuite struct {
	suite.Suite
	logger *zap.Logger
}

func (suite *MultiSchemesCRLLoaderSuite) SetupTest() {
	// Initialize the logger before each test
	logger, _ := zap.NewDevelopment()
	suite.logger = logger
}

func (suite *MultiSchemesCRLLoaderSuite) TestLoadCRL_Success() {
	// Create two mock loaders
	mockLoader1 := new(MockCRLLoader)
	mockLoader2 := new(MockCRLLoader)

	// Configure the first loader to succeed
	mockLoader1.On("LoadCRL", mock.Anything).Return(nil)

	// Create a MultiSchemesCRLLoader with the two loaders
	loader := MultiSchemesCRLLoader{
		Loaders: []CRLLoader{mockLoader1, mockLoader2},
		Logger:  suite.logger,
	}

	// Call the LoadCRL method
	err := loader.LoadCRL("test.crl")

	// Assert that the first loader was called and no error occurred
	assert.NoError(suite.T(), err)

	// Verify that the second loader was not called
	mockLoader2.AssertNotCalled(suite.T(), "LoadCRL", mock.Anything)
}

func (suite *MultiSchemesCRLLoaderSuite) TestLoadCRL_Failure() {
	// Create two mock loaders
	mockLoader1 := new(MockCRLLoader)
	mockLoader2 := new(MockCRLLoader)

	// Configure both loaders to fail
	mockLoader1.On("LoadCRL", mock.Anything).Return(fmt.Errorf("Loader 1 failed"))
	mockLoader2.On("LoadCRL", mock.Anything).Return(fmt.Errorf("Loader 2 failed"))
	// Configure both loaders to provide descriptions
	mockLoader1.On("GetDescription").Return("Loader 1")
	mockLoader2.On("GetDescription").Return("Loader 2")

	// Create a MultiSchemesCRLLoader with the two loaders
	loader := MultiSchemesCRLLoader{
		Loaders: []CRLLoader{mockLoader1, mockLoader2},
		Logger:  suite.logger,
	}

	// Call the LoadCRL method
	err := loader.LoadCRL("test.crl")

	// Assert that an error occurred and no loader was successful
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "failed to load CRL from all loaders")

	// Verify that both loaders were called
	mockLoader1.AssertCalled(suite.T(), "LoadCRL", "test.crl")
	mockLoader2.AssertCalled(suite.T(), "LoadCRL", "test.crl")
}

func (suite *MultiSchemesCRLLoaderSuite) TestLoadCRL_LastSuccessfulLoader() {
	// Create two mock loaders
	mockLoader1 := &MockCRLLoader{}
	mockLoader2 := &MockCRLLoader{}

	// Configure the first loader to fail initially and then succeed
	mockLoader1.On("LoadCRL", "test.crl").
		Return(fmt.Errorf("Loader 1 failed")). // Fails initially
		Once()                                 // Only called once

	// Configure the second loader to succeed
	mockLoader2.On("LoadCRL", "test.crl").Return(nil)

	mockLoader1.On("GetDescription").Return("Loader 1")
	mockLoader2.On("GetDescription").Return("Loader 2")

	// Create a MultiSchemesCRLLoader with the two loaders
	loader := &MultiSchemesCRLLoader{
		Loaders: []CRLLoader{mockLoader1, mockLoader2},
		Logger:  suite.logger,
	}

	// First load attempt (first loader fails, second loader succeeds)
	err := loader.LoadCRL("test.crl")
	assert.NoError(suite.T(), err)

	// Verify that both loades wre called
	mockLoader2.AssertCalled(suite.T(), "LoadCRL", "test.crl")
	mockLoader1.AssertCalled(suite.T(), "LoadCRL", "test.crl")

	mockLoader1.Calls = nil
	mockLoader2.Calls = nil
	mockLoader1.ExpectedCalls = nil

	// Now, configure the first loader to succeed
	mockLoader1.On("LoadCRL", "test.crl").Return(nil)

	// Second load attempt (second loader should be used as the last successful loader)
	err = loader.LoadCRL("test.crl")
	assert.NoError(suite.T(), err)

	// Verify that the second loader (last successful loader) was called
	mockLoader2.AssertCalled(suite.T(), "LoadCRL", "test.crl")
	mockLoader1.AssertNotCalled(suite.T(), "LoadCRL", "test.crl")
}

func (suite *MultiSchemesCRLLoaderSuite) TestGetCRLLocationIdentifier() {
	// Create two mock loaders
	mockLoader1 := new(MockCRLLoader)
	mockLoader2 := new(MockCRLLoader)

	// Configure the loaders to return identifiers
	mockLoader1.On("GetCRLLocationIdentifier").Return("Loader1Identifier", nil)
	mockLoader2.On("GetCRLLocationIdentifier").Return("Loader2Identifier", nil)

	// Create a MultiSchemesCRLLoader with the two loaders
	loader := MultiSchemesCRLLoader{
		Loaders: []CRLLoader{mockLoader1, mockLoader2},
		Logger:  suite.logger,
	}

	// Call the GetCRLLocationIdentifier method
	identifier, err := loader.GetCRLLocationIdentifier()

	// Assert that no error occurred and the identifiers are concatenated
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), "5c489d06cdb283469537650b99d9aebcbb96685df2ec3003c95704cf2d45924f", identifier)
}

func (suite *MultiSchemesCRLLoaderSuite) TestGetDescription() {
	// Create two mock loaders
	mockLoader1 := new(MockCRLLoader)
	mockLoader2 := new(MockCRLLoader)

	// Configure the loaders to return descriptions
	mockLoader1.On("GetDescription").Return("Loader 1")
	mockLoader2.On("GetDescription").Return("Loader 2")

	// Create a MultiSchemesCRLLoader with the two loaders
	loader := MultiSchemesCRLLoader{
		Loaders: []CRLLoader{mockLoader1, mockLoader2},
		Logger:  suite.logger,
	}

	// Call the GetDescription method
	description := loader.GetDescription()

	// Assert that the descriptions are concatenated
	assert.Equal(suite.T(), "Loader 1, Loader 2", description)
}

func TestMultiSchemesCRLLoaderSuite(t *testing.T) {
	// Run the test suite
	suite.Run(t, new(MultiSchemesCRLLoaderSuite))
}
