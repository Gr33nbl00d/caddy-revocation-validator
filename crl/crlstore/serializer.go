package crlstore

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/gr33nbl00d/caddy-tls-clr/core"
	"github.com/gr33nbl00d/caddy-tls-clr/crl/crlreader"
)

type Serializer interface {
	DeserializeMetaInfo([]byte) (*crlreader.CRLMetaInfo, error)
	SerializeMetaInfo(*crlreader.CRLMetaInfo) ([]byte, error)
	SerializeRevokedCert(*pkix.RevokedCertificate) ([]byte, error)
	DeserializeRevokedCert([]byte) (*pkix.RevokedCertificate, error)
	SerializeMetaInfoExt(*crlreader.ExtendedCRLMetaInfo) ([]byte, error)
	DeserializeMetaInfoExt([]byte) (*crlreader.ExtendedCRLMetaInfo, error)
	DeserializeSignatureCert([]byte) (*x509.Certificate, error)
	SerializeCRLLocations(*core.CRLLocations) ([]byte, error)
	DeserializeCRLLocations([]byte) (*core.CRLLocations, error)
}

type ASN1Serializer struct {
}

func (C ASN1Serializer) DeserializeMetaInfo(crlMetaBytes []byte) (*crlreader.CRLMetaInfo, error) {
	metaInfo := new(crlreader.CRLMetaInfo)
	_, err := asn1.Unmarshal(crlMetaBytes, metaInfo)
	if err != nil {
		return nil, err
	}
	return metaInfo, nil
}

func (C ASN1Serializer) SerializeMetaInfo(metaInfo *crlreader.CRLMetaInfo) ([]byte, error) {
	crlMetaInfoBytes, err := asn1.Marshal(*metaInfo)
	if err != nil {
		return nil, err
	}
	return crlMetaInfoBytes, nil
}

func (C ASN1Serializer) DeserializeRevokedCert(revokedCertBytes []byte) (*pkix.RevokedCertificate, error) {
	revokedCert := new(pkix.RevokedCertificate)
	_, err := asn1.Unmarshal(revokedCertBytes, revokedCert)
	if err != nil {
		return nil, err
	}
	return revokedCert, nil
}

func (C ASN1Serializer) SerializeRevokedCert(revokedCert *pkix.RevokedCertificate) ([]byte, error) {
	revokedCertBytes, err := asn1.Marshal(*revokedCert)
	if err != nil {
		return nil, err
	}
	return revokedCertBytes, nil
}

func (C ASN1Serializer) SerializeMetaInfoExt(metaInfo *crlreader.ExtendedCRLMetaInfo) ([]byte, error) {
	crlExtMetaInfoBytes, err := asn1.Marshal(*metaInfo)
	if err != nil {
		return nil, err
	}
	return crlExtMetaInfoBytes, nil
}

func (C ASN1Serializer) DeserializeMetaInfoExt(crlExtMetaBytes []byte) (*crlreader.ExtendedCRLMetaInfo, error) {
	extMetaInfo := new(crlreader.ExtendedCRLMetaInfo)
	_, err := asn1.Unmarshal(crlExtMetaBytes, extMetaInfo)
	if err != nil {
		return nil, err
	}
	return extMetaInfo, nil
}

func (C ASN1Serializer) SerializeSignatureCert(cert *x509.Certificate) ([]byte, error) {
	certBytes, err := asn1.Marshal(*cert)
	if err != nil {
		return nil, err
	}
	return certBytes, nil
}

func (C ASN1Serializer) DeserializeSignatureCert(certBytes []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

func (C ASN1Serializer) SerializeCRLLocations(crlLocations *core.CRLLocations) ([]byte, error) {
	bytes, err := asn1.Marshal(*crlLocations)
	if err != nil {
		return nil, err
	}
	return bytes, nil
}
func (C ASN1Serializer) DeserializeCRLLocations(certDistPointsBytes []byte) (*core.CRLLocations, error) {
	crlLocations := new(core.CRLLocations)
	_, err := asn1.Unmarshal(certDistPointsBytes, crlLocations)
	if err != nil {
		return nil, err
	}
	return crlLocations, nil
}
