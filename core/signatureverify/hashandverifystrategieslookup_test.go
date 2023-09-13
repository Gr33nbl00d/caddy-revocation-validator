package signatureverify

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SignatureVerifyTestSuite struct {
	suite.Suite
}

func TestSignatureVerifyTestSuite(t *testing.T) {
	suite.Run(t, new(SignatureVerifyTestSuite))
}

func (suite *SignatureVerifyTestSuite) TestLookupHashAndVerifyStrategies() {
	// Define a test case with a valid OID for RSA and SHA256
	oid := pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, // RSA with SHA256
	}

	// Call LookupHashAndVerifyStrategies with the test OID
	hvStrategies, err := LookupHashAndVerifyStrategies(oid)
	assert.NoError(suite.T(), err, "LookupHashAndVerifyStrategies should not return an error")

	// Ensure that the returned HashAndVerifyStrategies struct contains the expected values
	assert.Equal(suite.T(), crypto.SHA256, hvStrategies.HashStrategy, "HashStrategy should be SHA256")
	assert.IsType(suite.T(), &RSASignatureVerifyStrategy{}, hvStrategies.VerifyStrategy, "VerifyStrategy should be RSA")

	// Define a test case with a valid OID for ECDSA and SHA384
	oid = pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}, // ECDSA with SHA384
	}

	// Call LookupHashAndVerifyStrategies with the test OID
	hvStrategies, err = LookupHashAndVerifyStrategies(oid)
	assert.NoError(suite.T(), err, "LookupHashAndVerifyStrategies should not return an error")

	// Ensure that the returned HashAndVerifyStrategies struct contains the expected values
	assert.Equal(suite.T(), crypto.SHA384, hvStrategies.HashStrategy, "HashStrategy should be SHA384")
	assert.IsType(suite.T(), &ECDSASignatureVerifyStrategy{}, hvStrategies.VerifyStrategy, "VerifyStrategy should be ECDSA")

	// Define a test case with an invalid OID
	oid = pkix.AlgorithmIdentifier{
		Algorithm: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, // Invalid OID
	}

	// Call LookupHashAndVerifyStrategies with the invalid OID
	hvStrategies, err = LookupHashAndVerifyStrategies(oid)
	assert.Error(suite.T(), err, "LookupHashAndVerifyStrategies should return an error for an invalid OID")
	assert.Nil(suite.T(), hvStrategies, "HashAndVerifyStrategies should be nil for an invalid OID")
}
