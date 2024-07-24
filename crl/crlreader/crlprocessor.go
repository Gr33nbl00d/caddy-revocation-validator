package crlreader

import "github.com/gr33nbl00d/caddy-revocation-validator/core"

type CRLProcessor interface {
	StartUpdateCrl(crlMetaInfo *CRLMetaInfo) error
	InsertRevokedCertificate(entry *CRLEntry) error
	UpdateExtendedMetaInfo(info *ExtendedCRLMetaInfo) error
	UpdateSignatureCertificate(entry *core.CertificateChainEntry) error
}
