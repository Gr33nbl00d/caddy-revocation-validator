package crlreader

import (
	"testing"

	revocation "github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"github.com/stretchr/testify/assert"
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

func TestReadCRLWithoutCRLNumber(t *testing.T) {
	reader := StreamingCRLFileReader{}
	result, err := reader.ReadCRL(CRLPersisterProcessorMock{}, testhelper.GetTestDataFilePath("canocrl.crl"))
	assert.Nil(t, err)
	t.Logf("%v", result)
}

func TestReadCRLWithoutExtensions(t *testing.T) {
	reader := StreamingCRLFileReader{}
	result, err := reader.ReadCRL(CRLPersisterProcessorMock{}, testhelper.GetTestDataFilePath("canoext.crl"))
	assert.Nil(t, err)
	t.Logf("%v", result)
	t.Log(err)
}

// A crl without any extensions at all has no extension list at all. Looking
// for the certificate that signed it must not panic.
func TestFindCertificateIssuerCandidatesOfCRLWithoutExtensions(t *testing.T) {
	reader := StreamingCRLFileReader{}
	result, err := reader.ReadCRL(CRLPersisterProcessorMock{}, testhelper.GetTestDataFilePath("canoext.crl"))
	assert.Nil(t, err)
	assert.Nil(t, result.CRLExtensions)

	chains := &revocation.CertificateChains{}
	candidates, err := revocation.FindCertificateIssuerCandidates(
		result.Issuer,
		result.CRLExtensions,
		result.HashAndVerifyStrategy.VerifyStrategy.GetAlgorithmID(),
		chains)
	assert.Nil(t, err)
	assert.Len(t, candidates, 0)
}
