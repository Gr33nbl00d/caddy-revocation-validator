package signatureverify

import (
	"crypto"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
)

var oidToHashAlgorithmMap = map[string]crypto.Hash{
	"1.2.840.113549.1.1.5":  crypto.SHA1,   //sha1WithRSA
	"1.2.840.113549.1.1.14": crypto.SHA224, //sha224WithRSA
	"1.2.840.113549.1.1.11": crypto.SHA256, //sha256WithRSA
	"1.2.840.113549.1.1.12": crypto.SHA384, //sha384WithRSA
	"1.2.840.113549.1.1.13": crypto.SHA512, //sha512WithRSA
	"1.2.840.10045.4.1":     crypto.SHA1,   //ECDSAWithSHA1,
	"1.2.840.10045.4.3.1":   crypto.SHA224, //ECDSAWithSHA224,
	"1.2.840.10045.4.3.2":   crypto.SHA256, //ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   crypto.SHA384, //ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   crypto.SHA512, //ECDSAWithSHA512,
}

var oidPrefixToVerifyStrategyMap = map[string]SignatureVerifyStrategy{
	"1.2.840.113549": new(RSASignatureVerifyStrategy),   //RSA
	"1.2.840.10045":  new(ECDSASignatureVerifyStrategy), //ECDSA
}

func LookupHashAndVerifyStrategies(algoIdentifier pkix.AlgorithmIdentifier) (*HashAndVerifyStrategies, error) {
	h := new(HashAndVerifyStrategies)
	hashStrategy, err := getHashAlgorithmFromOID(algoIdentifier)
	if err != nil {
		return nil, err
	}
	h.HashStrategy = *hashStrategy
	h.VerifyStrategy = getVerifyStrategyFromOID(algoIdentifier)
	return h, nil
}

func getHashAlgorithmFromOID(target pkix.AlgorithmIdentifier) (*crypto.Hash, error) {
	for oidString, hash := range oidToHashAlgorithmMap {
		if strings.EqualFold(oidString, target.Algorithm.String()) {
			return &hash, nil
		}
	}
	return nil, errors.New(fmt.Sprintf("no valid hash algorithm is found for the oid: %#v", target))
}

func getVerifyStrategyFromOID(target pkix.AlgorithmIdentifier) SignatureVerifyStrategy {
	for oidPrefix, verifyStrategy := range oidPrefixToVerifyStrategyMap {
		if strings.HasPrefix(target.Algorithm.String(), oidPrefix) {
			return verifyStrategy
		}
	}
	return new(RSASignatureVerifyStrategy)
}
