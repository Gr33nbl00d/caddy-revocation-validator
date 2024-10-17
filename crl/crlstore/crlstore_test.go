package crlstore

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"os"
	"testing"
)

type CRLStoreSuite struct {
	suite.Suite
	logger *zap.Logger
	tmpDir string // Store the path to the temporary directory
}

func (suite *CRLStoreSuite) SetupTest() {
	// Initialize the logger before each test
	logger, _ := zap.NewDevelopment()
	suite.logger = logger

	// Create a temporary directory
	tmpDir, err := os.MkdirTemp("", "test-crl-dir-")
	assert.NoError(suite.T(), err, "Error creating temporary directory")
	suite.tmpDir = tmpDir
}

func (suite *CRLStoreSuite) TestCreateStoreFactoryMap() {
	factory, err := CreateStoreFactory(Map, suite.tmpDir, suite.logger, "")
	assert.NoError(suite.T(), err)
	assert.IsType(suite.T(), MapStoreFactory{}, factory)
	storeFactory := factory.(MapStoreFactory)
	assert.NotNil(suite.T(), storeFactory.Serializer)
	assert.Same(suite.T(), suite.logger, storeFactory.Logger)
}

func (suite *CRLStoreSuite) TestCreateStoreFactoryLevelDB() {
	factory, err := CreateStoreFactory(LevelDB, suite.tmpDir, suite.logger, "")
	assert.NoError(suite.T(), err)
	assert.IsType(suite.T(), LevelDbStoreFactory{}, factory)
	storeFactory := factory.(LevelDbStoreFactory)
	assert.NotNil(suite.T(), storeFactory.Serializer)
	assert.Same(suite.T(), suite.logger, storeFactory.Logger)
	assert.Equal(suite.T(), suite.tmpDir, storeFactory.BasePath)
}

func (suite *CRLStoreSuite) TestCreateStoreFactoryUnknownType() {
	factory, err := CreateStoreFactory(10, suite.tmpDir, suite.logger, "")
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), factory)
}

func TestCrlStoreSuite(t *testing.T) {
	// Run the test suite
	suite.Run(t, new(CRLStoreSuite))
}
