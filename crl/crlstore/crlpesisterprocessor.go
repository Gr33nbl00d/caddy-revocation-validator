package crlstore

import (
	revocation "github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
)

type CRLPersisterProcessor struct {
	CRLStore CRLStore
}

func (C CRLPersisterProcessor) StartUpdateCrl(crlMetaInfo *crlreader.CRLMetaInfo) error {
	return C.CRLStore.StartUpdateCrl(crlMetaInfo)
}

func (C CRLPersisterProcessor) InsertRevokedCertificate(entry *crlreader.CRLEntry) error {
	return C.CRLStore.InsertRevokedCert(entry)
}

func (C CRLPersisterProcessor) UpdateExtendedMetaInfo(info *crlreader.ExtendedCRLMetaInfo) error {
	return C.CRLStore.UpdateExtendedMetaInfo(info)
}

func (C CRLPersisterProcessor) UpdateSignatureCertificate(entry *revocation.CertificateChainEntry) error {
	return C.CRLStore.UpdateSignatureCertificate(entry)
}

func (C CRLPersisterProcessor) UpdateCRLLocations(crlLocations *revocation.CRLLocations) error {
	return C.CRLStore.UpdateCRLLocations(crlLocations)
}
