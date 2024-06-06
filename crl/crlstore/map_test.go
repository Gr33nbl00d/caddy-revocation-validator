package crlstore

import (
	pkix "crypto/x509/pkix"
	"encoding/asn1"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap/zaptest"
)

// MapStoreSuite is a test suite for the MapStore type.
type MapStoreSuite struct {
	suite.Suite
	store       *MapStore
	testIssuer  *pkix.RDNSequence
	revokedCert *pkix.RevokedCertificate
}

// SetupTest is called before each test method in the suite.
func (suite *MapStoreSuite) SetupTest() {
	logger := zaptest.NewLogger(suite.T())
	serializer := ASN1Serializer{}
	suite.store = &MapStore{
		Map:        make(map[string][]byte),
		Serializer: serializer,
		Logger:     logger,
	}

	suite.testIssuer = &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	serialBigInt := new(big.Int)
	serialBigInt.SetUint64(52314123)
	suite.revokedCert = &pkix.RevokedCertificate{
		SerialNumber:   serialBigInt,
		RevocationTime: time.Time{},
	}
}

// TearDownTest is called after each test method in the suite.
func (suite *MapStoreSuite) TearDownTest() {
	suite.store.Close()
}

// TestStartUpdateCrl tests the StartUpdateCrl method of MapStore.
func (suite *MapStoreSuite) TestStartUpdateCrl() {
	err := suite.store.StartUpdateCrl(&crlreader.CRLMetaInfo{})
	assert.NoError(suite.T(), err)
	// Add more assertions if needed
}

// TestInsertRevokedCert tests the InsertRevokedCert method of MapStore.
func (suite *MapStoreSuite) TestInsertRevokedCert() {
	err := suite.store.InsertRevokedCert(&crlreader.CRLEntry{Issuer: suite.testIssuer, RevokedCertificate: suite.revokedCert})
	assert.NoError(suite.T(), err)
	// Add more assertions if needed
}

// TestGetCertRevocationStatus tests the GetCertRevocationStatus method of MapStore.
func (suite *MapStoreSuite) TestGetCertRevocationStatus() {
	status, err := suite.store.GetCertRevocationStatus(suite.testIssuer, big.NewInt(123))
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), status)
	// Add more assertions if needed
}

// TestGetCRLMetaInfo tests the GetCRLMetaInfo method of MapStore.
func (suite *MapStoreSuite) TestGetCRLMetaInfo() {
	// No meta info set
	metaInfo, err := suite.store.GetCRLMetaInfo()
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), metaInfo)

	// Set meta info and check if retrieved properly
	err = suite.store.StartUpdateCrl(&crlreader.CRLMetaInfo{})
	assert.NoError(suite.T(), err)
	metaInfo, err = suite.store.GetCRLMetaInfo()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), metaInfo)
}

// TestGetCRLExtMetaInfo tests the GetCRLExtMetaInfo method of MapStore.
func (suite *MapStoreSuite) TestGetCRLExtMetaInfo() {
	// No extended meta info set
	extMetaInfo, err := suite.store.GetCRLExtMetaInfo()
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), extMetaInfo)

	// Set extended meta info and check if retrieved properly
	err = suite.store.UpdateExtendedMetaInfo(&crlreader.ExtendedCRLMetaInfo{})
	assert.NoError(suite.T(), err)
	extMetaInfo, err = suite.store.GetCRLExtMetaInfo()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), extMetaInfo)
}

// TestUpdateExtendedMetaInfo tests the UpdateExtendedMetaInfo method of MapStore.
func (suite *MapStoreSuite) TestUpdateExtendedMetaInfo() {
	// Update extended meta info and check if set properly
	extMetaInfo := &crlreader.ExtendedCRLMetaInfo{}
	err := suite.store.UpdateExtendedMetaInfo(extMetaInfo)
	assert.NoError(suite.T(), err)
}

// TestUpdateSignatureCertificate tests the UpdateSignatureCertificate method of MapStore.
func (suite *MapStoreSuite) TestUpdateSignatureCertificate() {
	// Update signature certificate and check if set properly
	entry := &core.CertificateChainEntry{}
	err := suite.store.UpdateSignatureCertificate(entry)
	assert.NoError(suite.T(), err)
}

// TestGetCRLSignatureCert tests the GetCRLSignatureCert method of MapStore.
func (suite *MapStoreSuite) TestGetCRLSignatureCert() {
	// No signature certificate set initially, expect error
	certEntry, err := suite.store.GetCRLSignatureCert()
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), certEntry)
	crtFile, err := os.Open(testhelper.GetTestDataFilePath("testcert.der"))
	assert.NoError(suite.T(), err)
	crtBytes, err := os.ReadFile(crtFile.Name())
	assert.NoError(suite.T(), err)
	defer utils.CloseWithErrorHandling(crtFile.Close)
	err = suite.store.UpdateSignatureCertificate(&core.CertificateChainEntry{RawCertificate: crtBytes})
	assert.NoError(suite.T(), err)
	certEntry, err = suite.store.GetCRLSignatureCert()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), certEntry)
}

// TestUpdateCRLLocations tests the UpdateCRLLocations method of MapStore.
func (suite *MapStoreSuite) TestUpdateCRLLocations() {
	// Update CRL locations and check if set properly
	crlLocations := &core.CRLLocations{}
	err := suite.store.UpdateCRLLocations(crlLocations)
	assert.NoError(suite.T(), err)
}

// TestGetCRLLocations tests the GetCRLLocations method of MapStore.
func (suite *MapStoreSuite) TestGetCRLLocations() {
	// No CRL locations set
	crlLocations, err := suite.store.GetCRLLocations()
	assert.Error(suite.T(), err)
	assert.Nil(suite.T(), crlLocations)

	// Set CRL locations and check if retrieved properly
	err = suite.store.UpdateCRLLocations(&core.CRLLocations{})
	assert.NoError(suite.T(), err)

	// Retrieve CRL locations and check if retrieved properly
	crlLocations, err = suite.store.GetCRLLocations()
	assert.NoError(suite.T(), err)
	assert.NotNil(suite.T(), crlLocations)
}

// TestUpdate tests the Update method of MapStore.
func (suite *MapStoreSuite) TestUpdate() {
	// Create a new MapStore instance to update from
	newStore := &MapStore{
		Map:        make(map[string][]byte),
		Serializer: suite.store.Serializer,
		Logger:     suite.store.Logger,
	}

	// Add some dummy data to the new store
	newStore.Map["dummy_key"] = []byte("dummy_value")
	expectedMapAfterUpdate := make(map[string][]byte)
	expectedMapAfterUpdate["dummy_key"] = []byte("dummy_value")

	// Call the Update method with the new store
	err := suite.store.Update(newStore)
	assert.NoError(suite.T(), err)

	// Check if the map of the original store has been updated to match the map of the new store
	assert.Equal(suite.T(), expectedMapAfterUpdate, suite.store.Map)

	// Ensure that the map in the new store object has been set to nil after the update
	assert.Nil(suite.T(), newStore.Map)
}

// TestIsEmpty tests the IsEmpty method of MapStore.
func (suite *MapStoreSuite) TestIsEmpty() {
	// Create a new empty MapStore instance
	store := &MapStore{
		Map:        make(map[string][]byte),
		Serializer: suite.store.Serializer,
		Logger:     suite.store.Logger,
	}

	// Check if the store is empty
	assert.True(suite.T(), store.IsEmpty())

	// Add some dummy data to the store
	store.Map["dummy_key"] = []byte("dummy_value")

	// Check if the store is not empty after adding data
	assert.False(suite.T(), store.IsEmpty())
}

// TestCreateStore tests the CreateStore method of MapStoreFactory.
func (suite *MapStoreSuite) TestCreateStore() {
	// Create a new MapStoreFactory instance
	factory := &MapStoreFactory{
		Serializer: ASN1Serializer{},
		Logger:     zaptest.NewLogger(suite.T()),
	}

	// Call the CreateStore method
	store, err := factory.CreateStore("", false)

	// Check if the method returns a non-nil store and no error
	assert.NotNil(suite.T(), store)
	assert.NoError(suite.T(), err)

	// Assert that the returned store is of type *MapStore
	_, ok := store.(*MapStore)
	assert.True(suite.T(), ok)
}

// TestDelete tests the Delete method of MapStore.
func (suite *MapStoreSuite) TestDelete() {
	// Create a new MapStore instance
	store := &MapStore{
		Map:        make(map[string][]byte),
		Serializer: suite.store.Serializer,
		Logger:     suite.store.Logger,
	}

	// Call the Delete method
	err := store.Delete()

	// Check if the method returns nil
	assert.Nil(suite.T(), err)
}

// TestSuite runs the test suite.
func TestSuite(t *testing.T) {
	suite.Run(t, new(MapStoreSuite))
}
