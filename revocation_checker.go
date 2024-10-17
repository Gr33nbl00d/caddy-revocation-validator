package revocation

import (
	"crypto/x509"
	"errors"
	"github.com/caddyserver/caddy/v2"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl"
	"github.com/gr33nbl00d/caddy-revocation-validator/ocsp"
	"go.uber.org/zap"
)

type RevocationChecker struct {
	RevocationConfig      *ParsedRevocationConfig
	crlRevocationChecker  *crl.CRLRevocationChecker
	ocspRevocationChecker *ocsp.OCSPRevocationChecker
}

func (c *RevocationChecker) Provision(ctx caddy.Context, logger *zap.Logger, revocationConfig *ParsedRevocationConfig) error {
	c.RevocationConfig = revocationConfig
	if c.RevocationConfig.IsCRLCheckingEnabled() {
		c.crlRevocationChecker = &crl.CRLRevocationChecker{}
	}
	c.ocspRevocationChecker = &ocsp.OCSPRevocationChecker{}

	if c.RevocationConfig.IsCRLCheckingEnabled() {
		logger.Info("crl checking was enabled start CRL provisioning")
		err := c.crlRevocationChecker.Provision(revocationConfig.CRLConfigParsed, logger, revocationConfig.ConfigHash)
		if err != nil {
			return err
		}
	}
	logger.Info("start ocsp provisioning")
	err := c.ocspRevocationChecker.Provision(revocationConfig.OCSOConfigParsed, logger)
	if err != nil {
		return err
	}
	return nil
}

func (c *RevocationChecker) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		clientCertificate := verifiedChains[0][0]
		if c.RevocationConfig.IsCRLCheckingEnabled() {
			revoked, err := c.ocspRevocationChecker.IsRevoked(clientCertificate, verifiedChains)
			if err != nil {
				return err
			}
			if revoked.Revoked {
				return errors.New("client certificate was revoked")
			}
		}
		if c.RevocationConfig.IsCRLCheckingEnabled() {
			revoked, err := c.crlRevocationChecker.IsRevoked(clientCertificate, verifiedChains)
			if err != nil {
				return err
			}
			if revoked.Revoked {
				return errors.New("client certificate was revoked")
			}
		}

	}
	return nil
}

func (c *RevocationChecker) Cleanup() error {
	if c.RevocationConfig.IsCRLCheckingEnabled() {
		err := c.crlRevocationChecker.Cleanup()
		if err != nil {
			return err
		}
	}
	err := c.ocspRevocationChecker.Cleanup()
	if err != nil {
		return err
	}
	return nil

}
