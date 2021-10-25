package signatureverify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"log"
	"math/big"
)

type ECDSASignatureVerifyStrategy struct {
}

type signature struct {
	R, S *big.Int
}

func (t ECDSASignatureVerifyStrategy) VerifySignature(_ crypto.Hash, key interface{}, calculatedSignature []byte, signatureBytes []byte) error {
	var ecdsaKey *ecdsa.PublicKey
	var ok bool

	if ecdsaKey, ok = key.(*ecdsa.PublicKey); !ok {
		return errors.New("not an ecdsa key")
	}

	var sig signature
	rest, err := asn1.Unmarshal(signatureBytes, &sig)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		log.Printf("[WARNING] more bytes found in signature than needed")
	}
	verify := ecdsa.Verify(ecdsaKey, calculatedSignature, sig.R, sig.S)
	if verify == false {
		return errors.New("signature verification failed")
	}
	return nil
}

func (t ECDSASignatureVerifyStrategy) GetAlgorithmID() x509.PublicKeyAlgorithm {
	return x509.ECDSA
}
