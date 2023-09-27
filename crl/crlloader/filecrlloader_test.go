package crlloader

import (
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type FileLoaderSuite struct {
	suite.Suite
	logger *zap.Logger
	tmpDir string // Store the path to the temporary directory
}

func (suite *FileLoaderSuite) SetupTest() {
	// Initialize the logger before each test
	logger, _ := zap.NewDevelopment()
	suite.logger = logger

	// Create a temporary directory
	tmpDir, err := ioutil.TempDir("", "test-crl-dir-")
	assert.NoError(suite.T(), err, "Error creating temporary directory")
	suite.tmpDir = tmpDir
}

func (suite *FileLoaderSuite) TearDownTest() {
	// Remove the temporary directory after each test

	utils.Retry(10, 3*time.Second, zap.NewExample(), func() error {
		err := os.RemoveAll(suite.tmpDir)
		assert.NoError(suite.T(), err, "Error removing temporary directory")
		return err
	})

}

func (suite *FileLoaderSuite) TestLoadCRL() {
	// Create a temporary CRL file within the temporary directory
	crlFile, err := ioutil.TempFile(suite.tmpDir, "test-crl-*.crl")
	// Write some data to the temporary file
	_, err = crlFile.WriteString("Test CRL Data")
	assert.NoError(suite.T(), err)
	err = crlFile.Close()
	assert.NoError(suite.T(), err, "Error creating temporary CRL file")
	defer os.Remove(crlFile.Name())

	// Create a FileLoader instance
	fileLoader := FileLoader{
		FileName: crlFile.Name(),
		Logger:   suite.logger,
	}

	// Define the path to copy the CRL to
	copyToPath := filepath.Join(suite.tmpDir, "copied-crl.crl")

	// Call the LoadCRL method
	err = fileLoader.LoadCRL(copyToPath)

	assert.NoError(suite.T(), err, "Error copying CRL")

	// Check if the CRL was copied correctly
	copiedCRLData, err := ioutil.ReadFile(copyToPath)

	assert.NoError(suite.T(), err, "Error reading copied CRL")
	assert.Equal(suite.T(), "Test CRL Data", string(copiedCRLData), "Copied CRL data doesn't match")
}

func (suite *FileLoaderSuite) TestLoadCRLWhereCRLIsDirectory() {
	// Create a temporary CRL file within the temporary directory
	crlFile, err := ioutil.TempFile(suite.tmpDir, "test-crl-*.crl")

	// Write some data to the temporary file
	_, err = crlFile.WriteString("Test CRL Data")
	assert.NoError(suite.T(), err)
	err = crlFile.Close()
	assert.NoError(suite.T(), err, "Error creating temporary CRL file")
	defer os.Remove(crlFile.Name())

	// Create a FileLoader instance
	fileLoader := FileLoader{
		FileName: suite.tmpDir,
		Logger:   suite.logger,
	}

	// Define the path to copy the CRL to
	copyToPath := filepath.Join(suite.tmpDir, "copied-crl.crl")

	// Call the LoadCRL method
	err = fileLoader.LoadCRL(copyToPath)
	assert.Error(suite.T(), err, "should return an error")
	assert.Contains(suite.T(), err.Error(), "after 5 attempts, last error: CRL File")
	assert.Contains(suite.T(), err.Error(), "is a directory")
}

func (suite *FileLoaderSuite) TestLoadCRLWhereCRLPathDoesNotExist() {

	// Create a temporary CRL file within the temporary directory
	crlFile, err := ioutil.TempFile(suite.tmpDir, "test-crl-*.crl")

	// Write some data to the temporary file
	_, err = crlFile.WriteString("Test CRL Data")
	assert.NoError(suite.T(), err)
	err = crlFile.Close()
	assert.NoError(suite.T(), err, "Error creating temporary CRL file")
	defer os.Remove(crlFile.Name())

	// Create a FileLoader instance
	fileLoader := FileLoader{
		FileName: crlFile.Name(),
		Logger:   suite.logger,
	}

	// Define the path to copy the CRL to
	copyToPath := filepath.Join(suite.tmpDir, "nonexistent/nonexsistent.crl")

	// Call the LoadCRL method
	err = fileLoader.LoadCRL(copyToPath)
	assert.Error(suite.T(), err, "should return an error")
	assert.Contains(suite.T(), err.Error(), "The system cannot find the path specified")
}

func (suite *FileLoaderSuite) TestLoadCRLWhereCRLTargetPathDoesNotExist() {

	invalidTargetPath := filepath.Join(suite.tmpDir, "nonexistent/nonexsistent.crl")
	// Create a FileLoader instance
	fileLoader := FileLoader{
		FileName: invalidTargetPath,
		Logger:   suite.logger,
	}

	// Define the path to copy the CRL to
	copyToPath := filepath.Join(suite.tmpDir, "copied-crl.crl")

	// Call the LoadCRL method
	err := fileLoader.LoadCRL(copyToPath)
	assert.Error(suite.T(), err, "should return an error")
	assert.Contains(suite.T(), err.Error(), "The system cannot find the path specified")
}

func (suite *FileLoaderSuite) TestGetCRLLocationIdentifier() {
	// Create a temporary CRL file within the temporary directory
	crlFile, err := ioutil.TempFile(suite.tmpDir, "test-crl-*.crl")
	assert.NoError(suite.T(), err, "Error creating temporary CRL file")
	err = crlFile.Close()
	assert.NoError(suite.T(), err, "Error creating temporary CRL file")
	defer os.Remove(crlFile.Name())

	// Create a FileLoader instance
	fileLoader := FileLoader{
		FileName: crlFile.Name(),
		Logger:   suite.logger,
	}

	// Call the GetCRLLocationIdentifier method
	identifier, err := fileLoader.GetCRLLocationIdentifier()
	assert.NoError(suite.T(), err, "Error getting CRL location identifier")
	assert.NotEmpty(suite.T(), identifier, "CRL location identifier is empty")
}

func (suite *FileLoaderSuite) TestGetDescription() {
	// Create a temporary CRL file within the temporary directory
	crlFile, err := ioutil.TempFile(suite.tmpDir, "test-crl-*.crl")
	assert.NoError(suite.T(), err, "Error creating temporary CRL file")
	err = crlFile.Close()
	assert.NoError(suite.T(), err, "Error creating temporary CRL file")
	defer os.Remove(crlFile.Name())

	// Create a FileLoader instance
	fileLoader := FileLoader{
		FileName: crlFile.Name(),
		Logger:   suite.logger,
	}

	// Call the GetDescription method
	description := fileLoader.GetDescription()
	assert.NotEmpty(suite.T(), description, "Description is empty")
}

func TestFileLoaderSuite(t *testing.T) {
	// Run the test suite
	suite.Run(t, new(FileLoaderSuite))
}
