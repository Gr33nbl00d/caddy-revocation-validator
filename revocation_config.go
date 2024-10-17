package revocation

import (
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
)

type ParsedRevocationConfig struct {
	ModeParsed       config.RevocationCheckMode
	CRLConfigParsed  *config.CRLConfigParsed
	OCSOConfigParsed *config.OCSPConfigParsed
	ConfigHash       string
}

func (c *ParsedRevocationConfig) IsOCSPCheckingEnabled() bool {
	return c.ModeParsed == config.RevocationCheckModePreferCRL || c.ModeParsed == config.RevocationCheckModePreferOCSP || c.ModeParsed == config.RevocationCheckModeOCSPOnly
}

func (c *ParsedRevocationConfig) IsCRLCheckingEnabled() bool {
	return c.ModeParsed == config.RevocationCheckModePreferCRL || c.ModeParsed == config.RevocationCheckModePreferOCSP || c.ModeParsed == config.RevocationCheckModeCRLOnly
}

type UnmarshalledRevocationConfig struct {
	Mode       string
	CRLConfig  *config.CRLConfig
	OCSPConfig *config.OCSPConfig
}
