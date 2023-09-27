package crlreader

import (
	revocation "github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"github.com/smallstep/assert"
	"testing"
)

type CRLPersisterProcessorMock struct {
}

func (C CRLPersisterProcessorMock) StartUpdateCrl(crlMetaInfo *CRLMetaInfo) error {
	return nil
}

func (C CRLPersisterProcessorMock) InsertRevokedCertificate(entry *CRLEntry) error {
	return nil
}

func (C CRLPersisterProcessorMock) UpdateExtendedMetaInfo(info *ExtendedCRLMetaInfo) error {
	return nil
}

func (C CRLPersisterProcessorMock) UpdateSignatureCertificate(entry *revocation.CertificateChainEntry) error {
	return nil
}

func (C CRLPersisterProcessorMock) UpdateCRLLocations(crlLocations *revocation.CRLLocations) error {
	return nil
}
func TestReadCRL(t *testing.T) {
	reader := StreamingCRLFileReader{}
	result, err := reader.ReadCRL(CRLPersisterProcessorMock{}, testhelper.GetTestDataFilePath("crl1.crl"))
	assert.Nil(t, err)
	t.Logf("%v", result)

}
