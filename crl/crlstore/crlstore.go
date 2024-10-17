package crlstore

import (
	"crypto/x509/pkix"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"go.uber.org/zap"
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
	Update(store CRLStore) error
	IsEmpty() bool
	Close()
	Delete() error
}

type Factory interface {
	CreateStore(identifier string, temporary bool) (CRLStore, error)
}

func CreateStoreFactory(storeType StoreType, repoBaseDir string, logger *zap.Logger, hash string) (Factory, error) {
	if storeType == Map {
		return MapStoreFactory{
			Serializer: ASN1Serializer{},
			Logger:     logger,
			ConfigHash: hash,
		}, nil
	} else if storeType == LevelDB {
		return LevelDbStoreFactory{
			Serializer: ASN1Serializer{},
			BasePath:   repoBaseDir,
			Logger:     logger,
			ConfigHash: hash,
		}, nil
	} else {
		return nil, fmt.Errorf("unknown store type %d", storeType)
	}
}
