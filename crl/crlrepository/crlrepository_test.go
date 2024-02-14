package crlrepository

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlloader"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlstore"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

const testCRLIdentifier = "myidentifier"

type TestingCRLLoaderFactory struct {
}

type TestingCrlLoader struct {
	crlLocations *core.CRLLocations
	logger       *zap.Logger
}

type TestingCRLReader struct {
}

func (t *TestingCRLReader) ReadCRL(crlProcessor crlreader.CRLProcessor, crlFilePath string) (*crlreader.CRLReadResult, error) {

	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	serialBigInt := new(big.Int)
	serialBigInt.SetUint64(52314123)

	crlProcessor.InsertRevokedCertificate(&crlreader.CRLEntry{
		issuer,
		&pkix.RevokedCertificate{
			SerialNumber:   serialBigInt,
			RevocationTime: time.Time{},
		},
	})
	return nil, nil
}

func (t *TestingCrlLoader) LoadCRL(targetFilePath string) error {
	crlPath := testhelper.GetTestDataFilePath("crl1.crl")
	err := copyToTargetFile(crlPath, targetFilePath)
	return err
}

func copyToTargetFile(sourceFileName string, targetFileName string) error {
	stat, err := os.Stat(sourceFileName)
	if err != nil {
		return err
	}
	if stat.IsDir() {
		return fmt.Errorf("CRL File %s is a directory", sourceFileName)
	}
	crlFile, err := os.OpenFile(targetFileName, os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer crlFile.Close()
	sourceFile, err := os.OpenFile(sourceFileName, os.O_RDONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	_, err = io.Copy(crlFile, sourceFile)
	if err != nil {
		return err
	}
	return nil
}

func (t *TestingCrlLoader) GetCRLLocationIdentifier() (string, error) {
	return testCRLIdentifier, nil
}

func (t *TestingCrlLoader) GetDescription() string {
	return "testing crl loader"
}

func (t TestingCRLLoaderFactory) CreatePreferredCrlLoader(crlLocations *core.CRLLocations, logger *zap.Logger) (crlloader.CRLLoader, error) {
	return &TestingCrlLoader{crlLocations, logger}, nil
}

func TestNewCRLRepositoryOfTypeMap(t *testing.T) {
	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{}
	storeType := crlstore.Map
	err, repo := NewCRLRepository(logger, crlConfig, storeType)
	assert.NoError(t, err)

	assert.NotNil(t, repo)
	assert.IsType(t, crlloader.DefaultCRLLoaderFactory{}, repo.crlLoaderFactory)
	assert.NotNil(t, repo.Factory)
	assert.IsType(t, crlstore.MapStoreFactory{}, repo.Factory)
	factory := repo.Factory.(crlstore.MapStoreFactory)
	assert.Equal(t, logger, factory.Logger)
	assert.IsType(t, crlstore.ASN1Serializer{}, factory.Serializer)
	assert.NotNil(t, repo.crlRepositoryLock)
	assert.NotNil(t, repo.crlRepository)
	assert.NotNil(t, repo.crlConfig)
	assert.NotNil(t, repo.logger)
	assert.NotNil(t, repo.crlReader)
	assert.IsType(t, crlreader.StreamingCRLFileReader{}, repo.crlReader)
}

func TestNewCRLRepositoryOfTypeLevelDB(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "crlnew_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{
		WorkDir: tempDir,
	}
	storeType := crlstore.LevelDB
	err, repo := NewCRLRepository(logger, crlConfig, storeType)
	assert.NoError(t, err)

	assert.NotNil(t, repo)
	assert.IsType(t, crlloader.DefaultCRLLoaderFactory{}, repo.crlLoaderFactory)
	assert.NotNil(t, repo.Factory)
	assert.IsType(t, crlstore.LevelDbStoreFactory{}, repo.Factory)
	factory := repo.Factory.(crlstore.LevelDbStoreFactory)
	assert.Equal(t, logger, factory.Logger)
	assert.Equal(t, tempDir, factory.BasePath)
	assert.IsType(t, crlstore.ASN1Serializer{}, factory.Serializer)
	assert.NotNil(t, repo.crlRepositoryLock)
	assert.NotNil(t, repo.crlRepository)
	assert.NotNil(t, repo.crlConfig)
	assert.NotNil(t, repo.logger)
}

func TestNewCRLRepositoryOfTypeUnknown(t *testing.T) {
	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{}
	storeType := 199
	err, _ := NewCRLRepository(logger, crlConfig, crlstore.StoreType(storeType))
	assert.Error(t, err)
}

func TestAddCRL(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "crl_test")
	if err != nil {
		t.Fatalf("Failed to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{
		WorkDir:   tempDir,
		CDPConfig: &config.CDPConfig{CRLFetchModeParsed: config.CRLFetchModeBackground},
	}
	storeType := crlstore.Map // or LevelDB
	err, repo := NewCRLRepository(logger, crlConfig, storeType)
	assert.NoError(t, err)
	chains := &core.CertificateChains{}
	crlLocations := &core.CRLLocations{CRLFile: "./test.crl"}

	// Call the AddCRL function
	crlAdded, err := repo.AddCRL(crlLocations, chains)

	assert.NoError(t, err)
	assert.True(t, crlAdded)
}

func TestIsRevokedNonStrict(t *testing.T) {
	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{
		CDPConfig: &config.CDPConfig{
			CRLCDPStrict: false,
		},
		// Set your CRLConfig properties here
	}
	storeType := crlstore.Map // or LevelDB
	factory, err := crlstore.CreateStoreFactory(storeType, crlConfig.WorkDir, logger)
	if err != nil {
		panic(err)
	}
	repo := Repository{factory,
		&sync.RWMutex{},
		make(map[string]*Entry),
		crlConfig,
		logger,
		TestingCRLLoaderFactory{},
		&TestingCRLReader{},
	}

	certificate := &x509.Certificate{}
	crlLocations := &core.CRLLocations{}

	// Call the IsRevoked function
	revocationStatus, err := repo.IsRevoked(certificate, crlLocations)

	assert.NoError(t, err)
	assert.NotNil(t, revocationStatus)
	assert.False(t, revocationStatus.Revoked)
}

func TestIsRevokedStrictButNotLoaded(t *testing.T) {
	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{
		CDPConfig: &config.CDPConfig{
			CRLCDPStrict: true,
		},
		// Set your CRLConfig properties here
	}
	storeType := crlstore.Map // or LevelDB
	factory, err := crlstore.CreateStoreFactory(storeType, crlConfig.WorkDir, logger)
	if err != nil {
		panic(err)
	}
	repo := Repository{factory,
		&sync.RWMutex{},
		make(map[string]*Entry),
		crlConfig,
		logger,
		TestingCRLLoaderFactory{},
		&TestingCRLReader{},
	}

	// Create a test Certificate and CRLLocations
	certificate := &x509.Certificate{}
	crlLocations := &core.CRLLocations{}

	// Call the IsRevoked function
	_, err = repo.IsRevoked(certificate, crlLocations)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "CRL defined in CDP was not loaded")
}

func TestIsRevokedStrictLoadedWithRevokedCert(t *testing.T) {
	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{
		CDPConfig: &config.CDPConfig{
			CRLCDPStrict: true,
		},
		// Set your CRLConfig properties here
	}
	storeType := crlstore.Map // or LevelDB
	factory, err := crlstore.CreateStoreFactory(storeType, crlConfig.WorkDir, logger)
	if err != nil {
		panic(err)
	}
	loaderFactory := TestingCRLLoaderFactory{}
	repo := Repository{factory,
		&sync.RWMutex{},
		make(map[string]*Entry),
		crlConfig,
		logger,
		loaderFactory,
		&TestingCRLReader{},
	}
	crlLocations := &core.CRLLocations{}

	loader, err := loaderFactory.CreatePreferredCrlLoader(nil, nil)
	assert.NoError(t, err)
	entry, b, err := repo.getOrAddEntry(testCRLIdentifier, loader, nil)
	assert.True(t, b)
	assert.NoError(t, err)
	err = repo.loadActively(entry, nil, crlLocations)
	assert.NoError(t, err)
	// Create a test Certificate and CRLLocations
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}

	issuerBytes, err := asn1.Marshal(*issuer)
	serialBigInt := new(big.Int)
	serialBigInt.SetUint64(52314123)

	certificate := &x509.Certificate{
		RawIssuer:    issuerBytes,
		SerialNumber: serialBigInt,
	}

	// Call the IsRevoked function
	revoked, err := repo.IsRevoked(certificate, crlLocations)

	assert.NoError(t, err)
	assert.True(t, revoked.Revoked)
	assert.NotNil(t, revoked.CRLRevokedCertEntry)
}

func TestIsRevokedStrictLoadedWithNonRevokedCert(t *testing.T) {
	logger := zap.NewNop()
	crlConfig := &config.CRLConfig{
		CDPConfig: &config.CDPConfig{
			CRLCDPStrict: true,
		},
		// Set your CRLConfig properties here
	}
	storeType := crlstore.Map // or LevelDB
	factory, err := crlstore.CreateStoreFactory(storeType, crlConfig.WorkDir, logger)
	if err != nil {
		panic(err)
	}
	loaderFactory := TestingCRLLoaderFactory{}
	repo := Repository{factory,
		&sync.RWMutex{},
		make(map[string]*Entry),
		crlConfig,
		logger,
		loaderFactory,
		&TestingCRLReader{},
	}
	crlLocations := &core.CRLLocations{}

	loader, err := loaderFactory.CreatePreferredCrlLoader(nil, nil)
	assert.NoError(t, err)
	entry, b, err := repo.getOrAddEntry(testCRLIdentifier, loader, nil)
	assert.True(t, b)
	assert.NoError(t, err)
	err = repo.loadActively(entry, nil, crlLocations)
	assert.NoError(t, err)
	// Create a test Certificate and CRLLocations
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}

	issuerBytes, err := asn1.Marshal(*issuer)
	serialBigInt := new(big.Int)
	serialBigInt.SetUint64(11314123)

	certificate := &x509.Certificate{
		RawIssuer:    issuerBytes,
		SerialNumber: serialBigInt,
	}

	// Call the IsRevoked function
	revoked, err := repo.IsRevoked(certificate, crlLocations)

	assert.NoError(t, err)
	assert.False(t, revoked.Revoked)
	assert.Nil(t, revoked.CRLRevokedCertEntry)
}

func TestUpdateCRLs(t *testing.T) {
	// Implement tests for UpdateCRLs function
}

func TestClose(t *testing.T) {
	// Implement tests for Close function
}

// You can add tests for other functions in a similar manner
