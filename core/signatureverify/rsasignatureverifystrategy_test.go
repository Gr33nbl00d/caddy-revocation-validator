package signatureverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type RSASignatureVerifySuite struct {
	suite.Suite
	strategy         RSASignatureVerifyStrategy
	privateKey       *rsa.PrivateKey
	publicKey        *rsa.PublicKey
	calculatedHash   []byte
	validSignature   []byte
	invalidSignature []byte
}

func (suite *RSASignatureVerifySuite) SetupSuite() {
	// Generate RSA key pair for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(suite.T(), err)

	suite.privateKey = privateKey
	suite.publicKey = &privateKey.PublicKey

	// Generate a message and calculate its hash
	message := []byte("Test message")
	hash := sha256.Sum256(message)
	suite.calculatedHash = hash[:]
}

func (suite *RSASignatureVerifySuite) SetupTest() {
	// Sign the message to generate a valid signature
	signature, err := rsa.SignPKCS1v15(rand.Reader, suite.privateKey, crypto.SHA256, suite.calculatedHash)
	assert.NoError(suite.T(), err)
	suite.validSignature = signature

	// Generate an invalid signature (modify the valid signature)
	invalidSignature := make([]byte, len(signature))
	copy(invalidSignature, signature)
	invalidSignature[10]++ // Modify the signature to make it invalid
	suite.invalidSignature = invalidSignature
}

func (suite *RSASignatureVerifySuite) TestValidSignature() {
	err := suite.strategy.VerifySignature(crypto.SHA256, suite.publicKey, suite.calculatedHash, suite.validSignature)
	assert.NoError(suite.T(), err, "Valid signature should be verified successfully")
}

func (suite *RSASignatureVerifySuite) TestInvalidSignature() {
	err := suite.strategy.VerifySignature(crypto.SHA256, suite.publicKey, suite.calculatedHash, suite.invalidSignature)
	assert.Error(suite.T(), err, "Invalid signature should result in an error")
}

func (suite *RSASignatureVerifySuite) TestWithWrongKeyType() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	suite.Require().NoError(err)

	err = suite.strategy.VerifySignature(crypto.SHA256, privateKey.PublicKey, nil, nil)
	assert.Error(suite.T(), err, "not an rsa key")
	assert.Contains(suite.T(), err.Error(), "not an rsa key")
}

func TestRSASignatureVerifySuite(t *testing.T) {
	suite.Run(t, new(RSASignatureVerifySuite))
}
