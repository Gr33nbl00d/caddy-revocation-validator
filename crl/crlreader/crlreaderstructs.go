package crlreader

import (
	"crypto/x509/pkix"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/asn1parser"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/signatureverify"
	"math/big"
	"time"
)

type CRLReadResult struct {
	HashAndVerifyStrategy *signatureverify.HashAndVerifyStrategies
	Signature             *asn1parser.BitString
	CalculatedSignature   []byte
	Issuer                *pkix.RDNSequence
	CRLExtensions         *[]pkix.Extension
}

type CRLMetaInfo struct {
	Issuer     pkix.RDNSequence
	ThisUpdate time.Time
	NextUpdate time.Time `asn1:"tag:0,optional"`
}

type ExtendedCRLMetaInfo struct {
	CRLNumber *big.Int `asn1:"tag:0,optional"`
}

type CRLEntry struct {
	Issuer             *pkix.RDNSequence
	RevokedCertificate *pkix.RevokedCertificate
}
