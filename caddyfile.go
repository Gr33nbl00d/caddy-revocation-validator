package revocation

import (
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"strconv"
)

type CertRevocationValidatorConfig struct {
	CRLConfig  *config.CRLConfig
	OCSPConfig *config.OCSPConfig
	Mode       string
}

func parseConfigFromCaddyfile(d *caddyfile.Dispenser) (*CertRevocationValidatorConfig, error) {
	// initialize structs
	crlConfig := config.CRLConfig{
		CDPConfig:                  &config.CDPConfig{},
		CRLUrls:                    []string{},
		CRLFiles:                   []string{},
		TrustedSignatureCertsFiles: []string{},
	}
	ocspConfig := config.OCSPConfig{
		TrustedResponderCertsFiles: []string{},
	}
	certRevocationValidatorConfig := CertRevocationValidatorConfig{
		OCSPConfig: &ocspConfig,
		CRLConfig:  &crlConfig,
	}

	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			key := d.Val()

			switch key {
			case "mode":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				certRevocationValidatorConfig.Mode = d.Val()
			case "crl_config":
				crlConfig, err := parseCaddyfileCRLConfig(d)
				if err != nil {
					return nil, err
				}
				certRevocationValidatorConfig.CRLConfig = crlConfig
			case "ocsp_config":
				ocspConfig, err := parseCaddyfileOCSPConfig(d)
				if err != nil {
					return nil, err
				}
				certRevocationValidatorConfig.OCSPConfig = ocspConfig
			default:
				return nil, d.Errf("unknown subdirective for the revocation verifier: %s", key)
			}
		}
	}
	return &certRevocationValidatorConfig, nil
}

func parseCaddyfileOCSPConfig(d *caddyfile.Dispenser) (*config.OCSPConfig, error) {
	ocspConfig := config.OCSPConfig{}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "default_cache_duration":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			ocspConfig.DefaultCacheDuration = d.Val()
		case "trusted_responder_cert_file":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			ocspConfig.TrustedResponderCertsFiles = append(ocspConfig.TrustedResponderCertsFiles, d.Val())
		case "ocsp_aia_strict":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			ocspConfig.OCSPAIAStrict = false
		default:
			return nil, d.Errf("unknown subdirective for the ocsp config in the revocation verifier: %s", d.Val())
		}
	}
	return &ocspConfig, nil
}

func parseCaddyfileCRLConfig(d *caddyfile.Dispenser) (*config.CRLConfig, error) {
	crlConfig := config.CRLConfig{}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "work_dir":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			crlConfig.WorkDir = d.Val()
		case "cdp_config":
			cdpConfig, err := parseCaddyfileCRLCDPConfig(d)
			if err != nil {
				return nil, err
			}
			crlConfig.CDPConfig = cdpConfig
		case "storage_type":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			crlConfig.StorageType = d.Val()
		case "update_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}

			crlConfig.UpdateInterval = d.Val()
		case "signature_validation_mode":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}

			crlConfig.SignatureValidationMode = d.Val()
		case "crl_url":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}

			crlConfig.CRLUrls = append(crlConfig.CRLUrls, d.Val())
		case "crl_file":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}

			crlConfig.CRLFiles = append(crlConfig.CRLFiles, d.Val())
		case "trusted_signature_cert_file":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}

			crlConfig.TrustedSignatureCertsFiles = append(crlConfig.TrustedSignatureCertsFiles, d.Val())
		default:
			return nil, d.Errf("unknown subdirective for the crl config in the revocation verifier: %s", d.Val())
		}
	}
	return &crlConfig, nil
}

func parseCaddyfileCRLCDPConfig(d *caddyfile.Dispenser) (*config.CDPConfig, error) {
	cdpConfig := config.CDPConfig{}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "crl_fetch_mode":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			cdpConfig.CRLFetchMode = d.Val()
		case "crl_cdp_strict":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}

			b, err := strconv.ParseBool(d.Val())
			if err != nil {
				return nil, d.ArgErr()
			}
			cdpConfig.CRLCDPStrict = b
		}
	}
	return &cdpConfig, nil
}
