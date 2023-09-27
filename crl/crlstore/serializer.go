package crlstore

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
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
