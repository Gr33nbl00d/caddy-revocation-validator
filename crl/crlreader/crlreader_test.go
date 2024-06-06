package crlreader

import (
	revocation "github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"github.com/smallstep/assert"
	"testing"
)

type CRLPersisterProcessorMock struct {
}

func (C CRLPersisterProcessorMock) StartUpdateCrl(_ *CRLMetaInfo) error {
	return nil
}

func (C CRLPersisterProcessorMock) InsertRevokedCertificate(_ *CRLEntry) error {
	return nil
}

func (C CRLPersisterProcessorMock) UpdateExtendedMetaInfo(_ *ExtendedCRLMetaInfo) error {
	return nil
}

func (C CRLPersisterProcessorMock) UpdateSignatureCertificate(_ *revocation.CertificateChainEntry) error {
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
func TestReadCRLWithPadding(t *testing.T) {
	reader := StreamingCRLFileReader{}
	result, err := reader.ReadCRL(CRLPersisterProcessorMock{}, testhelper.GetTestDataFilePath("crlpadding.pem"))
	assert.Nil(t, err)
	t.Logf("%v", result)
}
