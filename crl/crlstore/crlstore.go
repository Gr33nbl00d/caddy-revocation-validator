package crlstore

import (
	"crypto/x509/pkix"
	"github.com/gr33nbl00d/caddy-tls-clr/core"
	"github.com/gr33nbl00d/caddy-tls-clr/crl/crlreader"
	"math/big"
)

const ExtendedMetaInfoKey string = "#META#_EXT"
const MetaInfoKey string = "#META#"
const SignatureCertKey = "#CRL_SIG_CERT#"
const CRLLocationKey = "#CRL_LOCATIONS#"

type CRLStore interface {
	InsertRevokedCert(entry *crlreader.CRLEntry) error
	GetCertRevocationStatus(issuer *pkix.RDNSequence, certSerial *big.Int) (*core.RevocationStatus, error)
	StartUpdateCrl(info *crlreader.CRLMetaInfo) error
	GetCRLMetaInfo() (*crlreader.CRLMetaInfo, error)
	UpdateExtendedMetaInfo(extendedInfo *crlreader.ExtendedCRLMetaInfo) error
	GetCRLExtMetaInfo() (*crlreader.ExtendedCRLMetaInfo, error)
	UpdateSignatureCertificate(*core.CertificateChainEntry) error
	GetCRLSignatureCert() (*core.CertificateChainEntry, error)
	UpdateCRLLocations(points *core.CRLLocations) error
	GetCRLLocations() (*core.CRLLocations, error)
	Update(interface{}) error
	IsEmpty() bool
	Close()
	Delete() error
}

type Factory interface {
	CreateStore(identifier string, temporary bool) (CRLStore, error)
}
