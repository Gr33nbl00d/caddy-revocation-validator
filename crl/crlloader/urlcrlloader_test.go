package crlloader

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type URLLoaderSuite struct {
	suite.Suite
	logger *zap.Logger
}

func (suite *URLLoaderSuite) SetupTest() {
	// Initialize the logger before each test
	logger, _ := zap.NewDevelopment()
	suite.logger = logger
}

func (suite *URLLoaderSuite) TestLoadCRL() {
	// Create a temporary directory to store the downloaded CRL
	tmpDir, err := ioutil.TempDir("", "test-crl-dir-")
	assert.NoError(suite.T(), err, "Error creating temporary directory")
	defer os.RemoveAll(tmpDir)

	// Create a mock HTTP server that serves the CRL content
	mockCRLContent := "Mock CRL Data"
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(mockCRLContent))
	}))
	defer mockServer.Close()

	// Create a URLLoader instance
	urlLoader := URLLoader{
		UrlString: mockServer.URL,
		Logger:    suite.logger,
	}

	// Define the path to save the downloaded CRL
	downloadFilePath := filepath.Join(tmpDir, "downloaded-crl.crl")

	// Call the LoadCRL method
	err = urlLoader.LoadCRL(downloadFilePath)
	assert.NoError(suite.T(), err, "Error loading CRL")

	// Check if the downloaded CRL matches the expected content
	downloadedCRLData, err := ioutil.ReadFile(downloadFilePath)
	assert.NoError(suite.T(), err, "Error reading downloaded CRL")
	assert.Equal(suite.T(), mockCRLContent, string(downloadedCRLData), "Downloaded CRL content doesn't match")
}

func (suite *URLLoaderSuite) TestLoadCRLWithInvalidUrl() {
	// Create a temporary directory to store the downloaded CRL
	tmpDir, err := ioutil.TempDir("", "test-crl-dir-")
	assert.NoError(suite.T(), err, "Error creating temporary directory")
	defer os.RemoveAll(tmpDir)

	// Create a mock HTTP server that serves the CRL content
	mockCRLContent := "Mock CRL Data"
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(mockCRLContent))
	}))
	defer mockServer.Close()

	// Create a URLLoader instance
	urlLoader := URLLoader{
		UrlString: "httppppp:dsdsd",
		Logger:    suite.logger,
	}

	// Define the path to save the downloaded CRL
	downloadFilePath := filepath.Join(tmpDir, "downloaded-crl.crl")

	// Call the LoadCRL method
	err = urlLoader.LoadCRL(downloadFilePath)
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "unsupported protocol")
}

func (suite *URLLoaderSuite) TestGetCRLLocationIdentifier() {
	// Create a URLLoader instance
	urlLoader := URLLoader{
		UrlString: "http://example.com/crl",
		Logger:    suite.logger,
	}

	// Call the GetCRLLocationIdentifier method
	identifier, err := urlLoader.GetCRLLocationIdentifier()
	assert.NoError(suite.T(), err, "Error getting CRL location identifier")
	assert.NotEmpty(suite.T(), identifier, "CRL location identifier is empty")
}

func (suite *URLLoaderSuite) TestGetDescription() {
	// Create a URLLoader instance
	urlLoader := URLLoader{
		UrlString: "http://example.com/crl",
		Logger:    suite.logger,
	}

	// Call the GetDescription method
	description := urlLoader.GetDescription()
	assert.NotEmpty(suite.T(), description, "Description is empty")
}

func TestURLLoaderSuite(t *testing.T) {
	// Run the test suite
	suite.Run(t, new(URLLoaderSuite))
}
