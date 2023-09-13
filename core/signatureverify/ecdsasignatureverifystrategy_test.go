package signatureverify

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"log"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type ECDSASignatureVerifySuite struct {
	suite.Suite
	privateKey *ecdsa.PrivateKey
	publicKey  *ecdsa.PublicKey
}

func (suite *ECDSASignatureVerifySuite) SetupTest() {
	// Create a sample ECDSA key pair for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	suite.Require().NoError(err)

	suite.privateKey = privateKey
	suite.publicKey = &privateKey.PublicKey
}

func (suite *ECDSASignatureVerifySuite) TestValidSignature() {
	strategy := ECDSASignatureVerifyStrategy{}

	// Test GetAlgorithmID
	algorithmID := strategy.GetAlgorithmID()
	suite.Equal(x509.ECDSA, algorithmID)

	// Test VerifySignature with a valid signature
	message := []byte("Test message")
	r, s, err := ecdsa.Sign(rand.Reader, suite.privateKey, message)
	suite.Require().NoError(err)

	validSignature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	suite.Require().NoError(err)

	err = strategy.VerifySignature(crypto.SHA256, suite.publicKey, message, validSignature)
	suite.Nil(err)
}

func (suite *ECDSASignatureVerifySuite) TestInvalidSignature() {
	strategy := ECDSASignatureVerifyStrategy{}

	// Test VerifySignature with an invalid signature
	message := []byte("Test message")
	r, s, err := ecdsa.Sign(rand.Reader, suite.privateKey, message)
	suite.Require().NoError(err)

	invalidSignature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	suite.Require().NoError(err)

	// Modify the signature to make it invalid
	invalidSignature[10]++

	err = strategy.VerifySignature(crypto.SHA256, suite.publicKey, message, invalidSignature)
	assert.Error(suite.T(), err, "signature verification failed")
	assert.Contains(suite.T(), err.Error(), "signature verification failed")
}

type logCapture struct {
	buf *bytes.Buffer
}

func newLogCapture() *logCapture {
	return &logCapture{
		buf: new(bytes.Buffer),
	}
}

func (lc *logCapture) Write(p []byte) (n int, err error) {
	return lc.buf.Write(p)
}

func (suite *ECDSASignatureVerifySuite) TestTooLongSignature() {
	// Create a logCapture instance to capture log output
	capture := newLogCapture()

	// Replace the default log output with our custom logCapture
	log.SetOutput(capture)

	strategy := ECDSASignatureVerifyStrategy{}

	// Test GetAlgorithmID
	algorithmID := strategy.GetAlgorithmID()
	suite.Equal(x509.ECDSA, algorithmID)

	// Test VerifySignature with a valid signature
	message := []byte("Test message")
	r, s, err := ecdsa.Sign(rand.Reader, suite.privateKey, message)
	suite.Require().NoError(err)

	validSignature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	suite.Require().NoError(err)
	tooLongSignature := append(validSignature, 0xdd, 0xff, 0xdd, 0xee)

	err = strategy.VerifySignature(crypto.SHA256, suite.publicKey, message, tooLongSignature)
	suite.Nil(err)
	// Restore the default log output
	log.SetOutput(os.Stderr)

	// Check the captured log output for your expected message
	if !strings.Contains(capture.buf.String(), "[WARNING] more bytes found in signature than needed") {
		suite.Fail("Expected log message not found in log output")
	}
}

func (suite *ECDSASignatureVerifySuite) TestToFailWithWrongKeyImplementation() {
	strategy := ECDSASignatureVerifyStrategy{}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(suite.T(), err)

	err = strategy.VerifySignature(crypto.SHA256, privateKey.PublicKey, nil, nil)
	assert.Error(suite.T(), err, "not an ecdsa key")
}

func TestECDSASignatureVerifySuite(t *testing.T) {
	suite.Run(t, new(ECDSASignatureVerifySuite))
}
