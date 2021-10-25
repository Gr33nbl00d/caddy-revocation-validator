package core

import (
	"crypto/x509/pkix"
	"golang.org/x/crypto/ocsp"
)

type RevocationStatus struct {
	Revoked             bool
	CRLRevokedCertEntry *pkix.RevokedCertificate
	OcspResponse        *ocsp.Response
}
