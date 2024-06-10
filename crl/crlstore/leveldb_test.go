package crlstore

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/hashing"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type LevelDbStoreSuite struct {
	suite.Suite
	store             *LevelDbStore
	serializer        *ASN1Serializer
	logger            *zap.Logger
	testIssuer        *pkix.RDNSequence
	revokedCert       *pkix.RevokedCertificate
	revokedCertSerial *big.Int
}

func (suite *LevelDbStoreSuite) SetupTest() {
	suite.testIssuer = &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	suite.revokedCertSerial = new(big.Int)
	suite.revokedCertSerial.SetUint64(52314123)
	suite.revokedCert = &pkix.RevokedCertificate{
		SerialNumber:   suite.revokedCertSerial,
		RevocationTime: time.Time{},
	}

	suite.logger, _ = zap.NewDevelopment()
	suite.serializer = &ASN1Serializer{}
	tempDir, err := os.MkdirTemp("", "leveldbtest")
	assert.NoError(suite.T(), err)
	identifier := "testdb"
	levelDBPath := filepath.Join(tempDir, identifier)
	db, err := leveldb.OpenFile(levelDBPath, nil)
	suite.store = &LevelDbStore{
		Db:          db,
		Serializer:  suite.serializer,
		Identifier:  identifier,
		BasePath:    tempDir,
		LevelDBPath: levelDBPath,
		Logger:      suite.logger,
	}
}

func (suite *LevelDbStoreSuite) TearDownTest() {
	suite.store.Close()
	err := os.RemoveAll(suite.store.LevelDBPath)
	assert.NoError(suite.T(), err)
}

func (suite *LevelDbStoreSuite) TestStartUpdateCrl() {
	err := suite.store.StartUpdateCrl(&crlreader.CRLMetaInfo{})
	assert.NoError(suite.T(), err)
}

func (suite *LevelDbStoreSuite) TestInsertRevokedCert() {
	status, err := suite.store.GetCertRevocationStatus(suite.testIssuer, suite.revokedCertSerial)
	assert.NoError(suite.T(), err)
	assert.False(suite.T(), status.Revoked)

	err = suite.store.InsertRevokedCert(&crlreader.CRLEntry{
		Issuer:             suite.testIssuer,
		RevokedCertificate: suite.revokedCert,
	})
	assert.NoError(suite.T(), err)
	status, err = suite.store.GetCertRevocationStatus(suite.testIssuer, suite.revokedCertSerial)
	assert.NoError(suite.T(), err)
	assert.True(suite.T(), status.Revoked)
}
func (suite *LevelDbStoreSuite) TestIsEmpty() {
	// Initially, the store should be empty
	isEmpty := suite.store.IsEmpty()
	assert.True(suite.T(), isEmpty)

	// Insert some data into the store
	err := suite.store.StartUpdateCrl(&crlreader.CRLMetaInfo{})
	assert.NoError(suite.T(), err)

	// Now, the store should not be empty
	isEmpty = suite.store.IsEmpty()
	assert.False(suite.T(), isEmpty)
}

func (suite *LevelDbStoreSuite) TestGetCRLMetaInfo() {
	// Initially, there should be no CRL meta info
	metaInfo, err := suite.store.GetCRLMetaInfo()
	assert.Nil(suite.T(), metaInfo)
	assert.Error(suite.T(), err)

	// Insert some CRL meta info into the store
	thisUpdateTime := time.Date(2001, time.January, 1, 0, 0, 0, 0, time.UTC)
	nextUpdateTime := time.Date(2005, time.January, 1, 0, 0, 0, 0, time.UTC)
	expectedMetaInfo := &crlreader.CRLMetaInfo{
		Issuer:     *suite.testIssuer,
		ThisUpdate: thisUpdateTime,
		NextUpdate: nextUpdateTime,
	}
	err = suite.store.StartUpdateCrl(expectedMetaInfo)
	assert.NoError(suite.T(), err)

	// Retrieve the CRL meta info
	metaInfo, err = suite.store.GetCRLMetaInfo()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), metaInfo)
	assert.Equal(suite.T(), expectedMetaInfo, metaInfo)
}

func (suite *LevelDbStoreSuite) TestGetCRLExtMetaInfo() {
	// Initially, there should be no extended CRL meta info
	returnedMetaInfo, err := suite.store.GetCRLExtMetaInfo()
	assert.Nil(suite.T(), returnedMetaInfo)
	assert.Error(suite.T(), err)

	crlNumber := new(big.Int)
	crlNumber.SetUint64(52314123)

	// Insert some extended CRL meta info into the store
	expectedExtMetaInfo := &crlreader.ExtendedCRLMetaInfo{
		CRLNumber: crlNumber,
	}
	err = suite.store.UpdateExtendedMetaInfo(expectedExtMetaInfo)
	assert.NoError(suite.T(), err)

	// Retrieve the extended CRL meta info
	returnedMetaInfo, err = suite.store.GetCRLExtMetaInfo()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), returnedMetaInfo)
	assert.Equal(suite.T(), expectedExtMetaInfo, returnedMetaInfo)
}

func (suite *LevelDbStoreSuite) TestUpdateSignatureCertificate() {
	// Create a dummy certificate chain entry
	expectedCert := []byte{0x30, 0x82, 0x01, 0x0a} // replace with actual raw certificate bytes if needed
	certEntry := &core.CertificateChainEntry{
		RawCertificate: expectedCert,
	}

	// Update the signature certificate in the store
	err := suite.store.UpdateSignatureCertificate(certEntry)
	assert.NoError(suite.T(), err)

	// Retrieve the stored certificate to verify it was updated correctly
	hash := hashing.Sum64(SignatureCertKey)
	returnedCert, err := suite.store.Db.Get(hash, nil)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedCert, returnedCert)
}

func (suite *LevelDbStoreSuite) TestGetCRLSignatureCert() {
	testCertFile, err := os.Open(testhelper.GetTestDataFilePath("testcert.der"))
	assert.NoError(suite.T(), err)
	defer utils.CloseWithErrorHandling(testCertFile.Close)
	if err != nil {
		suite.T().Errorf("error occured %v", err)
	}
	testCertBytes, err := os.ReadFile(testCertFile.Name())

	// Store the serialized certificate in the LevelDbStore
	hash := hashing.Sum64(SignatureCertKey)
	err = suite.store.Db.Put(hash, testCertBytes, nil)
	assert.NoError(suite.T(), err)

	// Retrieve the certificate using the GetCRLSignatureCert method
	retrievedCertEntry, err := suite.store.GetCRLSignatureCert()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), retrievedCertEntry)

	// Verify the retrieved certificate matches the original
	assert.Equal(suite.T(), testCertBytes, retrievedCertEntry.Certificate.Raw)
}

func (suite *LevelDbStoreSuite) TestUpdateCRLLocations() {
	// Create a dummy CRLLocations
	crlLocations := &core.CRLLocations{
		CRLDistributionPoints: []string{"http://example.com/crl1", "http://example.com/crl2"},
	}

	// Update the CRL locations in the LevelDbStore
	err := suite.store.UpdateCRLLocations(crlLocations)
	assert.NoError(suite.T(), err)

	// Retrieve the stored CRL locations
	hash := hashing.Sum64(CRLLocationKey)
	crlLocationBytes, err := suite.store.Db.Get(hash, nil)
	assert.NoError(suite.T(), err)

	// Deserialize the retrieved CRL locations
	retrievedCRLLocations, err := suite.serializer.DeserializeCRLLocations(crlLocationBytes)
	assert.NoError(suite.T(), err)

	// Verify the retrieved CRL locations match the original
	assert.Equal(suite.T(), crlLocations, retrievedCRLLocations)
}

// TestGetCRLLocations tests the GetCRLLocations method of MapStore.
func (suite *LevelDbStoreSuite) TestGetCRLLocations() {
	// No CRL locations set
	returnedCrlLocations, err := suite.store.GetCRLLocations()
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), returnedCrlLocations)

	// Set CRL locations and check if retrieved properly
	expectedCrllocations := core.CRLLocations{CRLDistributionPoints: []string{"http://example.com/crl1", "http://example.com/crl2"}, CRLUrl: "http://test"}
	err = suite.store.UpdateCRLLocations(&expectedCrllocations)
	assert.NoError(suite.T(), err)

	// Retrieve CRL locations and check if retrieved properly
	returnedCrlLocations, err = suite.store.GetCRLLocations()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), returnedCrlLocations)
	assert.Equal(suite.T(), expectedCrllocations, *returnedCrlLocations)
}

func (suite *LevelDbStoreSuite) TestCreateStore() {
	factory := LevelDbStoreFactory{
		Serializer: suite.serializer,
		BasePath:   suite.store.BasePath,
		Logger:     suite.logger,
	}

	// Test creating a non-temporary store
	identifier := "non_temporary_store"
	store, err := factory.CreateStore(identifier, false)
	assert.NoError(suite.T(), err)

	levelDbStore, ok := store.(*LevelDbStore)
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), identifier, levelDbStore.Identifier)
	assert.Equal(suite.T(), suite.store.BasePath, levelDbStore.BasePath)
	assert.NotNil(suite.T(), levelDbStore.Db)

	// Verify the directory was created
	_, err = os.Stat(levelDbStore.LevelDBPath)
	assert.NoError(suite.T(), err)

	// Clean up
	err = levelDbStore.Db.Close()
	assert.NoError(suite.T(), err)
	err = os.RemoveAll(levelDbStore.LevelDBPath)
	assert.NoError(suite.T(), err)

	// Test creating a temporary store
	tempStore, err := factory.CreateStore(identifier, true)
	assert.NoError(suite.T(), err)

	levelDbTempStore, ok := tempStore.(*LevelDbStore)
	assert.True(suite.T(), ok)
	assert.Contains(suite.T(), levelDbTempStore.LevelDBPath, suite.store.BasePath)
	assert.NotNil(suite.T(), levelDbTempStore.Db)

	// Verify the temporary directory was created
	_, err = os.Stat(levelDbTempStore.LevelDBPath)
	assert.NoError(suite.T(), err)

	// Clean up
	err = levelDbTempStore.Db.Close()
	assert.NoError(suite.T(), err)
	err = os.RemoveAll(levelDbTempStore.LevelDBPath)
	assert.NoError(suite.T(), err)
}

func (suite *LevelDbStoreSuite) TestUpdate() {
	// Create a temporary directory for the new store
	tempDir, err := os.MkdirTemp("", "leveldbtest")
	assert.NoError(suite.T(), err)
	defer os.RemoveAll(tempDir) // Clean up the temporary directory

	// Create a new LevelDbStore instance to update from
	identifier := "newstore"
	levelDBPath := filepath.Join(tempDir, identifier)
	db, err := leveldb.OpenFile(levelDBPath, nil)
	assert.NoError(suite.T(), err)
	newStore := &LevelDbStore{
		Db:          db,
		Serializer:  suite.store.Serializer,
		Identifier:  identifier,
		BasePath:    tempDir,
		LevelDBPath: levelDBPath,
		Logger:      suite.store.Logger,
	}

	// Add some dummy data to the new store
	dummyKey := "dummy_key"
	dummyValue := []byte("dummy_value")
	hash := hashing.Sum64(dummyKey)
	err = newStore.Db.Put(hash, dummyValue, nil)
	assert.NoError(suite.T(), err)

	// Call the Update method with the new store
	err = suite.store.Update(newStore)
	assert.NoError(suite.T(), err)

	// Check if the data in the original store has been updated to match the data in the new store
	retrievedValue, err := suite.store.Db.Get(hash, nil)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), dummyValue, retrievedValue)

	// Ensure that the new store's database has been closed
	_, err = newStore.Db.Get(hash, nil)
	assert.Error(suite.T(), err, "leveldb: closed")

	// Ensure that the old store's database has been closed
	_, err = newStore.Db.Get(hash, nil)
	assert.Error(suite.T(), err, "leveldb: closed")
}

func (suite *LevelDbStoreSuite) TestDelete() {
	// Add some dummy data to the store
	dummyKey := "dummy_key"
	dummyValue := []byte("dummy_value")
	hash := hashing.Sum64(dummyKey)
	err := suite.store.Db.Put(hash, dummyValue, nil)
	assert.NoError(suite.T(), err)

	// Ensure the dummy data is in the store
	retrievedValue, err := suite.store.Db.Get(hash, nil)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), dummyValue, retrievedValue)

	//close the store
	suite.store.Close()

	// Call the Delete method
	err = suite.store.Delete()
	assert.NoError(suite.T(), err)

	// Check if the LevelDB path has been removed
	_, err = os.Stat(suite.store.LevelDBPath)
	assert.True(suite.T(), os.IsNotExist(err), "expected LevelDB path to be removed")

	// Check if trying to get data from the store returns an error
	_, err = suite.store.Db.Get(hash, nil)
	assert.Error(suite.T(), err)
}

func TestLevelDbStoreSuite(t *testing.T) {
	suite.Run(t, new(LevelDbStoreSuite))
}
