package revocation

import (
	"log"
	"strconv"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
)

func (c *CertRevocationValidator) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// initialize structs
	crlConfg := config.CRLConfig{
		CDPConfig:                  &config.CDPConfig{},
		CRLUrls:                    []string{},
		CRLFiles:                   []string{},
		TrustedSignatureCertsFiles: []string{},
	}
	ocspConfig := config.OCSPConfig{
		TrustedResponderCertsFiles: []string{},
	}
	c.CRLConfig = &crlConfg
	c.OCSPConfig = &ocspConfig
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			key := d.Val()

			log.Printf("key: %v", key)
			switch key {
			case "mode":
				if !d.NextArg() {
					return d.ArgErr()
				}

				c.Mode = d.Val()

			case "crl_config":
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "work_dir":
						if !d.NextArg() {
							return d.ArgErr()
						}

						crlConfg.WorkDir = d.Val()
					case "crl_fetch_mode":
						if !d.NextArg() {
							return d.ArgErr()
						}

						crlConfg.CDPConfig.CRLFetchMode = d.Val()
					case "crl_cdp_strict":
						if !d.NextArg() {
							return d.ArgErr()
						}

						b, err := strconv.ParseBool(d.Val())
						if err != nil {
							return d.ArgErr()
						}
						crlConfg.CDPConfig.CRLCDPStrict = b
						// ...
					case "storage_type":
						if !d.NextArg() {
							return d.ArgErr()
						}

						crlConfg.StorageType = d.Val()
					case "update_interval":
						if !d.NextArg() {
							return d.ArgErr()
						}

						crlConfg.UpdateInterval = d.Val()
					case "signature_validation_mode":
						if !d.NextArg() {
							return d.ArgErr()
						}

						crlConfg.SignatureValidationMode = d.Val()
					case "crl_url":
						if !d.NextArg() {
							return d.ArgErr()
						}

						crlConfg.CRLUrls = append(crlConfg.CRLUrls, d.Val())
					case "crl_file":
						if !d.NextArg() {
							return d.ArgErr()
						}

						crlConfg.CRLFiles = append(crlConfg.CRLFiles, d.Val())
					case "trusted_signature_cert_file":
						if !d.NextArg() {
							return nil
						}

						crlConfg.TrustedSignatureCertsFiles = append(crlConfg.TrustedSignatureCertsFiles, d.Val())
					default:
						return d.Errf("unknown subdirective for the crl config in the revocation verifier: %s", d.Val())
					}
				}
			case "ocsp_config":
				for nesting := d.Nesting(); d.NextBlock(nesting); {
					switch d.Val() {
					case "default_cache_duration":
						if !d.NextArg() {
							return nil
						}

						ocspConfig.DefaultCacheDuration = d.Val()
					case "trusted_responder_cert_file":
						if !d.NextArg() {
							return nil
						}

						ocspConfig.TrustedResponderCertsFiles = append(ocspConfig.TrustedResponderCertsFiles, d.Val())
					case "ocsp_aia_strict":
						if !d.NextArg() {
							return nil
						}

						ocspConfig.OCSPAIAStrict = false

					default:
						return d.Errf("unknown subdirective for the ocsp config in the revocation verifier: %s", d.Val())
					}
				}
			default:
				return d.Errf("unknown subdirective for the revocation verifier: %s", key)
			}
		}
	}
	return nil
}
