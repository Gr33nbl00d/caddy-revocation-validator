package signatureverify

import (
	"crypto"
	"crypto/x509"
)

type SignatureVerifyStrategy interface {
	VerifySignature(hash crypto.Hash, key interface{}, calculatedSignature []byte, signature []byte) error
	GetAlgorithmID() x509.PublicKeyAlgorithm
}

type HashAndVerifyStrategies struct {
	VerifyStrategy SignatureVerifyStrategy
	HashStrategy   crypto.Hash
}
