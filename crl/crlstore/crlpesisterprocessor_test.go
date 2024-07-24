package crlstore

import (
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"crypto/x509/pkix"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"math/big"
)

// MockCRLStore is a mock implementation of CRLStore for testing purposes
type MockCRLStore struct {
	mock.Mock
}

func (m *MockCRLStore) InsertRevokedCert(entry *crlreader.CRLEntry) error {
	args := m.Called(entry)
	return args.Error(0)
}

func (m *MockCRLStore) GetCertRevocationStatus(issuer *pkix.RDNSequence, certSerial *big.Int) (*core.RevocationStatus, error) {
	args := m.Called(issuer, certSerial)
	if args.Get(1) == nil {
		return args.Get(0).(*core.RevocationStatus), nil
	}
	return nil, args.Error(1)
}

func (m *MockCRLStore) StartUpdateCrl(info *crlreader.CRLMetaInfo) error {
	args := m.Called(info)
	return args.Error(0)
}

func (m *MockCRLStore) GetCRLMetaInfo() (*crlreader.CRLMetaInfo, error) {
	args := m.Called()
	if args.Get(1) == nil {
		return args.Get(0).(*crlreader.CRLMetaInfo), nil
	}
	return nil, args.Error(1)
}

func (m *MockCRLStore) UpdateExtendedMetaInfo(extendedInfo *crlreader.ExtendedCRLMetaInfo) error {
	args := m.Called(extendedInfo)
	return args.Error(0)
}

func (m *MockCRLStore) GetCRLExtMetaInfo() (*crlreader.ExtendedCRLMetaInfo, error) {
	args := m.Called()
	if args.Get(1) == nil {
		return args.Get(0).(*crlreader.ExtendedCRLMetaInfo), nil
	}
	return nil, args.Error(1)
}

func (m *MockCRLStore) UpdateSignatureCertificate(entry *core.CertificateChainEntry) error {
	args := m.Called(entry)
	return args.Error(0)
}

func (m *MockCRLStore) GetCRLSignatureCert() (*core.CertificateChainEntry, error) {
	args := m.Called()
	if args.Get(1) == nil {
		return args.Get(0).(*core.CertificateChainEntry), nil
	}
	return nil, args.Error(1)
}

func (m *MockCRLStore) UpdateCRLLocations(points *core.CRLLocations) error {
	args := m.Called(points)
	return args.Error(0)
}

func (m *MockCRLStore) GetCRLLocations() (*core.CRLLocations, error) {
	args := m.Called()
	if args.Get(1) == nil {
		return args.Get(0).(*core.CRLLocations), nil
	}
	return nil, args.Error(1)
}

func (m *MockCRLStore) Update(store CRLStore) error {
	args := m.Called(store)
	return args.Error(0)
}

func (m *MockCRLStore) IsEmpty() bool {
	args := m.Called()
	return args.Bool(0)
}

func (m *MockCRLStore) Close() {
	m.Called()
}

func (m *MockCRLStore) Delete() error {
	args := m.Called()
	return args.Error(0)
}

// CRLPersisterProcessorTestSuite is the test suite for CRLPersisterProcessor
type CRLPersisterProcessorTestSuite struct {
	suite.Suite
	processor *CRLPersisterProcessor
	mockStore *MockCRLStore
}

func (suite *CRLPersisterProcessorTestSuite) SetupTest() {
	// Create a mock CRLStore
	suite.mockStore = new(MockCRLStore)
	suite.processor = &CRLPersisterProcessor{
		CRLStore: suite.mockStore,
	}
}

func (suite *CRLPersisterProcessorTestSuite) TestStartUpdateCrl() {
	// Mock behavior of CRLStore's StartUpdateCrl method
	metaInfo := &crlreader.CRLMetaInfo{}
	suite.mockStore.On("StartUpdateCrl", metaInfo).Return(nil)

	// Call the method under test
	err := suite.processor.StartUpdateCrl(metaInfo)

	// Assert that the method returns nil error
	suite.NoError(err)

	// Verify that StartUpdateCrl was called with the correct argument
	suite.mockStore.AssertCalled(suite.T(), "StartUpdateCrl", metaInfo)
}

func (suite *CRLPersisterProcessorTestSuite) TestInsertRevokedCertificate() {
	// Mock behavior of CRLStore's InsertRevokedCert method
	entry := &crlreader.CRLEntry{}
	suite.mockStore.On("InsertRevokedCert", entry).Return(nil)

	// Call the method under test
	err := suite.processor.InsertRevokedCertificate(entry)

	// Assert that the method returns nil error
	suite.NoError(err)

	// Verify that InsertRevokedCert was called with the correct argument
	suite.mockStore.AssertCalled(suite.T(), "InsertRevokedCert", entry)
}

func (suite *CRLPersisterProcessorTestSuite) TestUpdateExtendedMetaInfo() {
	// Mock behavior of CRLStore's UpdateExtendedMetaInfo method
	info := &crlreader.ExtendedCRLMetaInfo{}
	suite.mockStore.On("UpdateExtendedMetaInfo", info).Return(nil)

	// Call the method under test
	err := suite.processor.UpdateExtendedMetaInfo(info)

	// Assert that the method returns nil error
	suite.NoError(err)

	// Verify that UpdateExtendedMetaInfo was called with the correct argument
	suite.mockStore.AssertCalled(suite.T(), "UpdateExtendedMetaInfo", info)
}

func (suite *CRLPersisterProcessorTestSuite) TestUpdateSignatureCertificate() {
	// Mock behavior of CRLStore's UpdateSignatureCertificate method
	entry := &core.CertificateChainEntry{}
	suite.mockStore.On("UpdateSignatureCertificate", entry).Return(nil)

	// Call the method under test
	err := suite.processor.UpdateSignatureCertificate(entry)

	// Assert that the method returns nil error
	suite.NoError(err)

	// Verify that UpdateSignatureCertificate was called with the correct argument
	suite.mockStore.AssertCalled(suite.T(), "UpdateSignatureCertificate", entry)
}

func (suite *CRLPersisterProcessorTestSuite) TestUpdateCRLLocations() {
	// Mock behavior of CRLStore's UpdateCRLLocations method
	crlLocations := &core.CRLLocations{}
	suite.mockStore.On("UpdateCRLLocations", crlLocations).Return(nil)

	// Call the method under test
	err := suite.processor.UpdateCRLLocations(crlLocations)

	// Assert that the method returns nil error
	suite.NoError(err)

	// Verify that UpdateCRLLocations was called with the correct argument
	suite.mockStore.AssertCalled(suite.T(), "UpdateCRLLocations", crlLocations)
}
func TestCRLPersisterProcessorTestSuite(t *testing.T) {
	suite.Run(t, new(CRLPersisterProcessorTestSuite))
}
