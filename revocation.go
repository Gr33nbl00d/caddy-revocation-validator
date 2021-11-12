package revocation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl"
	"github.com/gr33nbl00d/caddy-revocation-validator/ocsp"
	"go.uber.org/zap"
	"os"
)

func init() {
	caddy.RegisterModule(CertRevocationValidator{})
}

type CertRevocationValidator struct {
	Mode                  string             `json:"mode"`
	CRLConfig             *config.CRLConfig  `json:"crl_config,omitempty"`
	OCSPConfig            *config.OCSPConfig `json:"ocsp_config,omitempty"`
	logger                *zap.Logger
	ctx                   caddy.Context
	crlRevocationChecker  *crl.CRLRevocationChecker
	ocspRevocationChecker *ocsp.OCSPRevocationChecker
	ModeParsed            config.RevocationCheckMode `json:"-"`
}

func (c CertRevocationValidator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.client_cert_validators.revocation",
		New: func() caddy.Module {
			return new(CertRevocationValidator)
		},
	}
}

// Provision sets up c
func (c *CertRevocationValidator) Provision(ctx caddy.Context) error {
	c.ctx = ctx
	c.logger = ctx.Logger(c)
	if isCRLCheckingEnabled(c) {
		c.crlRevocationChecker = &crl.CRLRevocationChecker{}
	}
	c.ocspRevocationChecker = &ocsp.OCSPRevocationChecker{}
	err := ParseConfig(c)
	if err != nil {
		return err
	}
	err = validateConfig(c)
	if err != nil {
		return err
	}
	if isCRLCheckingEnabled(c) {
		err = c.crlRevocationChecker.Provision(c.CRLConfig, c.logger)
		if err != nil {
			return err
		}
	}
	err = c.ocspRevocationChecker.Provision(c.OCSPConfig, c.logger)
	if err != nil {
		return err
	}

	return nil
}

func validateConfig(c *CertRevocationValidator) error {
	if c.ModeParsed == config.RevocationCheckModeDisabled {
		return nil
	}
	if isCRLCheckingEnabled(c) {
		if c.CRLConfig == nil {
			return errors.New("For CRL checking a working directory need to be defined in crl_config")
		} else {
			if c.CRLConfig.WorkDir == "" {
				return errors.New("For CRL checking a working directory need to be defined in crl_config")
			}
			stat, err := os.Stat(c.CRLConfig.WorkDir)
			if err != nil {
				return fmt.Errorf("error accessing working directory information %v", err)
			}
			if stat.IsDir() == false {
				return fmt.Errorf("working directory is not a directory %v", c.CRLConfig.WorkDir)
			}
		}
	}
	return nil
}

func (c *CertRevocationValidator) Cleanup() error {
	if isCRLCheckingEnabled(c) {
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

func (c *CertRevocationValidator) VerifyClientCertificate(_ [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		clientCertificate := verifiedChains[0][0]
		if isOCSPCheckingEnabled(c) {
			revoked, err := c.ocspRevocationChecker.IsRevoked(clientCertificate, verifiedChains)
			if err != nil {
				return err
			}
			if revoked.Revoked {
				return errors.New("client certificate was revoked")
			}
		}
		if isCRLCheckingEnabled(c) {
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

func isOCSPCheckingEnabled(c *CertRevocationValidator) bool {
	return c.ModeParsed == config.RevocationCheckModePreferCRL || c.ModeParsed == config.RevocationCheckModePreferOCSP || c.ModeParsed == config.RevocationCheckModeOCSPOnly
}

func isCRLCheckingEnabled(c *CertRevocationValidator) bool {
	return c.ModeParsed == config.RevocationCheckModePreferCRL || c.ModeParsed == config.RevocationCheckModePreferOCSP || c.ModeParsed == config.RevocationCheckModeCRLOnly
}

// Interface guards
var (
	_ caddy.Provisioner            = (*CertRevocationValidator)(nil)
	_ caddy.CleanerUpper           = (*CertRevocationValidator)(nil)
	_ caddytls.ClientCertValidator = (*CertRevocationValidator)(nil)
)
