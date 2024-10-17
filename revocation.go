package revocation

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"go.uber.org/zap"
	"os"
)

func init() {
	caddy.RegisterModule(&CertRevocationValidator{})
}

// CertRevocationValidator Allows checking of client certificate revocation status based on CRL or OCSP
type CertRevocationValidator struct {
	// Mode defines the "Revocation Check Mode"
	// Supported Values 'prefer_ocsp', 'prefer_crl', 'ocsp_only', 'crl_only', 'disabled'
	// See https://github.com/Gr33nbl00d/caddy-revocation-validator#mode
	Mode string `json:"mode"`
	// CRLConfig Contains the certificate revocation list configuration (Optional)
	CRLConfig *config.CRLConfig `json:"crl_config,omitempty"`
	// OCSPConfig Contains the Online Certificate Status Protocol configuration (Optional)
	OCSPConfig             *config.OCSPConfig `json:"ocsp_config,omitempty"`
	logger                 *zap.Logger
	ctx                    caddy.Context
	parsedRevocationConfig *ParsedRevocationConfig
}

func (c *CertRevocationValidator) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID: "tls.client_auth.verifier.revocation",
		New: func() caddy.Module {
			return new(CertRevocationValidator)
		},
	}
}

// Provision sets up c
func (c *CertRevocationValidator) Provision(ctx caddy.Context) error {
	c.ctx = ctx
	c.logger = ctx.Logger(c)
	c.logger.Info("start provisioning of caddy revocation validator")
	unmarshalledRevocationConfig := &UnmarshalledRevocationConfig{c.Mode, c.CRLConfig, c.OCSPConfig}
	parsedRevocationConfig, err := ParseConfig(unmarshalledRevocationConfig, c.logger)
	c.parsedRevocationConfig = parsedRevocationConfig
	if err != nil {
		return err
	}

	c.logger.Info("validating Config")
	err = validateConfig(parsedRevocationConfig)
	if err != nil {
		return err
	}

	RevocationCheckerRepositoryInstance.Provision(ctx, c.logger, c.parsedRevocationConfig)

	c.logger.Info("finished provisioning of caddy revocation validator")
	return nil
}

func validateConfig(c *ParsedRevocationConfig) error {
	if c.ModeParsed == config.RevocationCheckModeDisabled {
		return nil
	}
	if c.IsCRLCheckingEnabled() {
		if c.CRLConfigParsed == nil {
			return errors.New("for CRL checking a working directory need to be defined in crl_config")
		} else {
			if c.CRLConfigParsed.WorkDir == "" {
				return errors.New("for CRL checking a working directory need to be defined in crl_config")
			}
			stat, err := os.Stat(c.CRLConfigParsed.WorkDir)
			if err != nil {
				return fmt.Errorf("error accessing working directory information %v", err)
			}
			if stat.IsDir() == false {
				return fmt.Errorf("working directory is not a directory %v", c.CRLConfigParsed.WorkDir)
			}
		}
	}
	return nil
}

func (c *CertRevocationValidator) Cleanup() error {
	return RevocationCheckerRepositoryInstance.Cleanup(c.parsedRevocationConfig)
}

func (c *CertRevocationValidator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	unmarshalledConfig, err := parseConfigFromCaddyfile(d)
	if err != nil {
		return err
	}
	c.OCSPConfig = unmarshalledConfig.OCSPConfig
	c.CRLConfig = unmarshalledConfig.CRLConfig
	c.Mode = unmarshalledConfig.Mode
	return nil
}

func (c *CertRevocationValidator) VerifyClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return RevocationCheckerRepositoryInstance.VerifyClientCertificate(c.parsedRevocationConfig, rawCerts, verifiedChains)
}

// Interface guards
var (
	_ caddy.Provisioner                  = (*CertRevocationValidator)(nil)
	_ caddy.CleanerUpper                 = (*CertRevocationValidator)(nil)
	_ caddytls.ClientCertificateVerifier = (*CertRevocationValidator)(nil)
)
