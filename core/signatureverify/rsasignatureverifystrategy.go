package signatureverify

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

type RSASignatureVerifyStrategy struct {
}

func (t RSASignatureVerifyStrategy) VerifySignature(hash crypto.Hash, key interface{}, calculatedSignature []byte, signature []byte) error {
	var rsaKey *rsa.PublicKey
	var ok bool

	if rsaKey, ok = key.(*rsa.PublicKey); !ok {
		return errors.New("not an rsa key")
	}
	err := rsa.VerifyPKCS1v15(rsaKey, hash, calculatedSignature, signature)
	return err
}

func (t RSASignatureVerifyStrategy) GetAlgorithmID() x509.PublicKeyAlgorithm {
	return x509.RSA
}
