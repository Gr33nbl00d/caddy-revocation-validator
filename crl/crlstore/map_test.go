package crlstore

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/hashing"
	"github.com/stretchr/testify/mock"
	"math/big"
	"testing"

	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
)

type MockSerializer struct {
	mock.Mock
}

func (m *MockSerializer) DeserializeMetaInfo(data []byte) (*crlreader.CRLMetaInfo, error) {
	args := m.Called(data)
	return args.Get(0).(*crlreader.CRLMetaInfo), args.Error(1)
}

func (m *MockSerializer) SerializeMetaInfo(info *crlreader.CRLMetaInfo) ([]byte, error) {
	args := m.Called(info)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSerializer) SerializeRevokedCert(cert *pkix.RevokedCertificate) ([]byte, error) {
	args := m.Called(cert)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSerializer) DeserializeRevokedCert(data []byte) (*pkix.RevokedCertificate, error) {
	args := m.Called(data)
	return args.Get(0).(*pkix.RevokedCertificate), args.Error(1)
}

func (m *MockSerializer) SerializeMetaInfoExt(info *crlreader.ExtendedCRLMetaInfo) ([]byte, error) {
	args := m.Called(info)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSerializer) DeserializeMetaInfoExt(data []byte) (*crlreader.ExtendedCRLMetaInfo, error) {
	args := m.Called(data)
	return args.Get(0).(*crlreader.ExtendedCRLMetaInfo), args.Error(1)
}

func (m *MockSerializer) DeserializeSignatureCert(data []byte) (*x509.Certificate, error) {
	args := m.Called(data)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

func (m *MockSerializer) SerializeCRLLocations(locations *core.CRLLocations) ([]byte, error) {
	args := m.Called(locations)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSerializer) DeserializeCRLLocations(data []byte) (*core.CRLLocations, error) {
	args := m.Called(data)
	return args.Get(0).(*core.CRLLocations), args.Error(1)
}

type MapStoreTestSuite struct {
	suite.Suite
	store      *MapStore
	serializer *MockSerializer
	logger     *zap.Logger
}

func (suite *MapStoreTestSuite) SetupTest() {
	suite.logger = zap.NewNop()
	suite.serializer = new(MockSerializer)
	suite.store = &MapStore{
		Map:        make(map[string][]byte),
		Serializer: suite.serializer,
		Logger:     suite.logger,
	}
}

func (suite *MapStoreTestSuite) TestStartUpdateCrl_Success() {
	info := &crlreader.CRLMetaInfo{}
	suite.serializer.On("SerializeMetaInfo", info).Return([]byte("serialized"), nil)

	err := suite.store.StartUpdateCrl(info)
	suite.Nil(err)
	suite.NotNil(suite.store.Map[string(hashing.Sum64(MetaInfoKey))])
}

func (suite *MapStoreTestSuite) TestStartUpdateCrl_SerializeError() {
	info := &crlreader.CRLMetaInfo{}
	suite.serializer.On("SerializeMetaInfo", info).Return(([]byte)(nil), errors.New("serialize error"))

	err := suite.store.StartUpdateCrl(info)
	suite.NotNil(err)
	suite.Contains(err.Error(), "could not serialize CRLMetaInfo")
}

func (suite *MapStoreTestSuite) TestInsertRevokedCert_Success() {
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}

	entry := &crlreader.CRLEntry{
		Issuer: issuer,
		RevokedCertificate: &pkix.RevokedCertificate{
			SerialNumber: big.NewInt(12345),
		},
	}
	serialKey := entry.Issuer.String() + "_" + entry.RevokedCertificate.SerialNumber.String()
	suite.serializer.On("SerializeRevokedCert", entry.RevokedCertificate).Return([]byte("serialized"), nil)

	err := suite.store.InsertRevokedCert(entry)
	suite.Nil(err)
	suite.NotNil(suite.store.Map[string(hashing.Sum64(serialKey))])
}

func (suite *MapStoreTestSuite) TestInsertRevokedCert_SerializeError() {
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}

	entry := &crlreader.CRLEntry{
		Issuer: issuer,
		RevokedCertificate: &pkix.RevokedCertificate{
			SerialNumber: big.NewInt(12345),
		},
	}
	suite.serializer.On("SerializeRevokedCert", entry.RevokedCertificate).Return(([]byte)(nil), errors.New("serialize error"))

	err := suite.store.InsertRevokedCert(entry)
	suite.NotNil(err)
	suite.Contains(err.Error(), "could not serialize CRLEntry")
}

func (suite *MapStoreTestSuite) TestGetCertRevocationStatus_Revoked() {
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	serial := big.NewInt(12345)
	serialKey := issuer.String() + "_" + serial.String()
	revokedCert := &pkix.RevokedCertificate{}
	suite.store.Map[string(hashing.Sum64(serialKey))] = []byte("serialized")
	suite.serializer.On("DeserializeRevokedCert", []byte("serialized")).Return(revokedCert, nil)

	status, err := suite.store.GetCertRevocationStatus(issuer, serial)
	suite.Nil(err)
	suite.True(status.Revoked)
	suite.Equal(revokedCert, status.CRLRevokedCertEntry)
}

func (suite *MapStoreTestSuite) TestGetCertRevocationStatus_NotRevoked() {
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	serial := big.NewInt(12345)

	status, err := suite.store.GetCertRevocationStatus(issuer, serial)
	suite.Nil(err)
	suite.False(status.Revoked)
	suite.Nil(status.CRLRevokedCertEntry)
}

func (suite *MapStoreTestSuite) TestGetCertRevocationStatus_DeserializeError() {

	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	revokedCert := &pkix.RevokedCertificate{
		SerialNumber: big.NewInt(12345),
	}
	serial := big.NewInt(12345)
	serialKey := issuer.String() + "_" + serial.String()
	suite.store.Map[string(hashing.Sum64(serialKey))] = []byte("serialized")
	suite.serializer.On("DeserializeRevokedCert", []byte("serialized")).Return(revokedCert, errors.New("deserialize error"))

	status, err := suite.store.GetCertRevocationStatus(issuer, serial)
	suite.NotNil(err)
	suite.Contains(err.Error(), "could not deserialize revoked cert")
	suite.Nil(status)
}

func (suite *MapStoreTestSuite) TestUpdateExtendedMetaInfo_Success() {
	info := &crlreader.ExtendedCRLMetaInfo{}
	suite.serializer.On("SerializeMetaInfoExt", info).Return([]byte("serialized"), nil)

	err := suite.store.UpdateExtendedMetaInfo(info)
	suite.Nil(err)
	suite.NotNil(suite.store.Map[string(hashing.Sum64(ExtendedMetaInfoKey))])
}

func (suite *MapStoreTestSuite) TestUpdateExtendedMetaInfo_SerializeError() {
	info := &crlreader.ExtendedCRLMetaInfo{}
	suite.serializer.On("SerializeMetaInfoExt", info).Return(([]byte)(nil), errors.New("serialize error"))

	err := suite.store.UpdateExtendedMetaInfo(info)
	suite.NotNil(err)
	suite.Contains(err.Error(), "could not serialize ExtendedCRLMetaInfo")
}

func (suite *MapStoreTestSuite) TestGetCRLMetaInfo_Success() {
	metaInfo := &crlreader.CRLMetaInfo{}
	suite.store.Map[string(hashing.Sum64(MetaInfoKey))] = []byte("serialized")
	suite.serializer.On("DeserializeMetaInfo", []byte("serialized")).Return(metaInfo, nil)

	info, err := suite.store.GetCRLMetaInfo()
	suite.Nil(err)
	suite.Equal(metaInfo, info)
}

func (suite *MapStoreTestSuite) TestGetCRLExtMetaInfo_Success() {
	expectedMetaInfo := &crlreader.ExtendedCRLMetaInfo{}
	serializedMetaInfo := []byte("serializedExtendedMetaInfo")

	suite.store.Map[string(hashing.Sum64(ExtendedMetaInfoKey))] = serializedMetaInfo
	suite.serializer.On("DeserializeMetaInfoExt", serializedMetaInfo).Return(expectedMetaInfo, nil)

	result, err := suite.store.GetCRLExtMetaInfo()
	suite.Nil(err)
	suite.Equal(expectedMetaInfo, result)
	suite.serializer.AssertExpectations(suite.T())
}

func (suite *MapStoreTestSuite) TestGetCRLExtMetaInfo_NotFound() {
	result, err := suite.store.GetCRLExtMetaInfo()
	suite.NotNil(err)
	suite.Nil(result)
	suite.Contains(err.Error(), "entry not found")
}

func (suite *MapStoreTestSuite) TestGetCRLExtMetaInfo_DeserializeError() {
	serializedMetaInfo := []byte("serializedExtendedMetaInfo")
	suite.store.Map[string(hashing.Sum64(ExtendedMetaInfoKey))] = serializedMetaInfo

	suite.serializer.On("DeserializeMetaInfoExt", serializedMetaInfo).Return((*crlreader.ExtendedCRLMetaInfo)(nil), errors.New("deserialize error"))

	result, err := suite.store.GetCRLExtMetaInfo()
	suite.NotNil(err)
	suite.Nil(result)
	suite.Contains(err.Error(), "deserialize error")
	suite.serializer.AssertExpectations(suite.T())
}
func (suite *MapStoreTestSuite) TestGetCRLMetaInfo_NotFound() {
	info, err := suite.store.GetCRLMetaInfo()
	suite.NotNil(err)
	suite.Nil(info)
}

func (suite *MapStoreTestSuite) TestUpdateSignatureCertificate_Success() {
	entry := &core.CertificateChainEntry{
		RawCertificate: []byte("raw cert"),
	}
	suite.store.Map[string(hashing.Sum64(SignatureCertKey))] = entry.RawCertificate

	err := suite.store.UpdateSignatureCertificate(entry)
	suite.Nil(err)
	suite.NotNil(suite.store.Map[string(hashing.Sum64(SignatureCertKey))])
}

func (suite *MapStoreTestSuite) TestGetCRLSignatureCert_Success() {
	cert := &x509.Certificate{}
	suite.store.Map[string(hashing.Sum64(SignatureCertKey))] = []byte("serialized")
	suite.serializer.On("DeserializeSignatureCert", []byte("serialized")).Return(cert, nil)

	entry, err := suite.store.GetCRLSignatureCert()
	suite.Nil(err)
	suite.NotNil(entry)
	suite.Equal(cert, entry.Certificate)
}

func (suite *MapStoreTestSuite) TestGetCRLSignatureCert_NotFound() {
	entry, err := suite.store.GetCRLSignatureCert()
	suite.NotNil(err)
	suite.Nil(entry)
	suite.Contains(err.Error(), "could not find signature key for crl")
}

func (suite *MapStoreTestSuite) TestGetCRLSignatureCert_DeserializeError() {

	certificate := &x509.Certificate{}
	suite.store.Map[string(hashing.Sum64(SignatureCertKey))] = []byte("serialized")
	suite.serializer.On("DeserializeSignatureCert", []byte("serialized")).Return(certificate, errors.New("deserialize error"))

	entry, err := suite.store.GetCRLSignatureCert()
	suite.NotNil(err)
	suite.Nil(entry)
	suite.Contains(err.Error(), "could not deserialize CRL signature certificate")
}

func (suite *MapStoreTestSuite) TestUpdateCRLLocations_Success() {
	locations := &core.CRLLocations{}
	suite.serializer.On("SerializeCRLLocations", locations).Return([]byte("serialized"), nil)

	err := suite.store.UpdateCRLLocations(locations)
	suite.Nil(err)
	suite.NotNil(suite.store.Map[string(hashing.Sum64(CRLLocationKey))])
}

func (suite *MapStoreTestSuite) TestUpdateCRLLocations_SerializeError() {
	locations := &core.CRLLocations{}
	suite.serializer.On("SerializeCRLLocations", locations).Return(([]byte)(nil), errors.New("serialize error"))

	err := suite.store.UpdateCRLLocations(locations)
	suite.NotNil(err)
	suite.Contains(err.Error(), "could not serialize CRLLocations")
}

func (suite *MapStoreTestSuite) TestGetCRLLocations_Success() {
	locations := &core.CRLLocations{}
	suite.store.Map[string(hashing.Sum64(CRLLocationKey))] = []byte("serialized")
	suite.serializer.On("DeserializeCRLLocations", []byte("serialized")).Return(locations, nil)

	result, err := suite.store.GetCRLLocations()
	suite.Nil(err)
	suite.Equal(locations, result)
}

func (suite *MapStoreTestSuite) TestGetCRLLocations_NotFound() {
	result, err := suite.store.GetCRLLocations()
	suite.NotNil(err)
	suite.Nil(result)
}

func (suite *MapStoreTestSuite) TestIsEmpty_True() {
	suite.True(suite.store.IsEmpty())
}

func (suite *MapStoreTestSuite) TestIsEmpty_False() {
	suite.store.Map["key"] = []byte("value")
	suite.False(suite.store.IsEmpty())
}

func (suite *MapStoreTestSuite) TestUpdate_Success() {
	otherStore := &MapStore{
		Map: map[string][]byte{
			"key1": []byte("value1"),
			"key2": []byte("value2"),
		},
		Serializer: suite.serializer,
		Logger:     suite.logger,
	}
	otherStoreExpected := &MapStore{
		Map: map[string][]byte{
			"key1": []byte("value1"),
			"key2": []byte("value2"),
		},
		Serializer: suite.serializer,
		Logger:     suite.logger,
	}

	err := suite.store.Update(otherStore)
	suite.Nil(err)
	suite.Equal(otherStoreExpected.Map, suite.store.Map)
	suite.Empty(otherStore.Map)
}

func (suite *MapStoreTestSuite) TestMapStoreFactory_CreateStore() {
	// Mock serializer and logger
	serializer := new(MockSerializer)
	logger := zap.NewNop()

	// Create a MapStoreFactory instance
	factory := MapStoreFactory{
		Serializer: serializer,
		Logger:     logger,
	}

	// Call CreateStore method
	store, err := factory.CreateStore("", false)

	// Assertions
	suite.NoError(err)  // Ensure no error occurred
	suite.NotNil(store) // Ensure store is not nil

	// Type assertion to check if store is of type *MapStore
	mapStore, ok := store.(*MapStore)
	suite.True(ok) // Ensure type assertion was successful

	// Additional assertions to verify initial state of MapStore
	suite.Empty(mapStore.Map)                    // Ensure Map is initially empty
	suite.Equal(serializer, mapStore.Serializer) // Ensure Serializer is correctly set
	suite.Equal(logger, mapStore.Logger)         // Ensure Logger is correctly set
}

func (suite *MapStoreTestSuite) TestClose() {
	// Call the Close method
	suite.store.Close()

	// Ensure no modifications to Map or other fields
	// For simplicity, we assert no specific changes here since Close() does nothing
}

func (suite *MapStoreTestSuite) TestDelete() {
	// Call the Delete method
	err := suite.store.Delete()

	// Assert that Delete() returns nil
	suite.NoError(err)
}
func TestMapStoreTestSuite(t *testing.T) {
	suite.Run(t, new(MapStoreTestSuite))
}
