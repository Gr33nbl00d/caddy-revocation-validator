package config

import (
	"crypto/x509"
	"time"
)

type CRLFetchMode int

const (
	CRLFetchModeActively CRLFetchMode = iota
	CRLFetchModeBackground
)

type SignatureValidationMode int

const (
	SignatureValidationModeNone SignatureValidationMode = iota
	SignatureValidationModeVerifyLog
	SignatureValidationModeVerify
)

type StorageType int

const (
	Memory StorageType = iota
	Disk
)

type RevocationCheckMode int

const (
	RevocationCheckModePreferOCSP RevocationCheckMode = iota
	RevocationCheckModePreferCRL
	RevocationCheckModeCRLOnly
	RevocationCheckModeOCSPOnly
	RevocationCheckModeDisabled
)

type CDPConfig struct {
	// CRLFetchMode Configures how and when CRLs are downloaded for the first time
	// Supported Values: 'fetch_actively', 'fetch_background'
	// See: https://github.com/Gr33nbl00d/caddy-revocation-validator#crl_fetch_mode
	CRLFetchMode string `json:"crl_fetch_mode,omitempty"`
	// CRLCDPStrict Configures if CRL checking is mandatory to allow a connection if CDP is defined (Optional) (Default: false)
	// See: https://github.com/Gr33nbl00d/caddy-revocation-validator#crl_cdp_strict
	CRLCDPStrict bool `json:"crl_cdp_strict,omitempty"`
	// Configures how and when CRLs are downloaded for the first time
	// Supported Values: 'fetch_actively', 'fetch_background'
	// See: https://github.com/Gr33nbl00d/caddy-revocation-validator#crl_fetch_mode
	CRLFetchModeParsed CRLFetchMode `json:"-"`
}

type CRLConfig struct {
	// WorkDir Configures the working directory for temporary CRL downloads and for disk based persistent CRLs
	WorkDir string `json:"work_dir"`
	// CDPConfig Configures how CDP (Certificate Distribution Point Extension) entries in the client certificate are used
	CDPConfig *CDPConfig `json:"cdp_config,omitempty"`
	// StorageType Configures how to store CRLs locally (Optional)
	// Supported Values: 'memory', 'disk' Default: 'disk'
	// See: https://github.com/Gr33nbl00d/caddy-revocation-validator#storage_type
	StorageType string `json:"storage_type,omitempty"`
	// UpdateInterval The interval in which the already known CRLs will be updated. (Optional) (Default: 30 minutes)
	// Valid time units are “ns”, “us” (or “µs”), “ms”, “s”, “m”, “h”
	// See: https://pkg.go.dev/time#ParseDuration
	UpdateInterval string `json:"update_interval,omitempty"`
	// Configures the signature validation or the CRL (Optional) (Default: 'verify')
	// Supported Values: 'none', 'verify', 'verify_log'
	// See: https://github.com/Gr33nbl00d/caddy-revocation-validator#signature_validation_mode
	SignatureValidationMode string `json:"signature_validation_mode,omitempty"`
	// CRLUrls (Optional) A predefined list of http(s) urls pointing to CRLs. These lists will be checked for all client certificates.
	// The predefined CRLs will be loaded on startup and updated cyclic.
	// PEM and DER encoding are both supported
	CRLUrls []string `json:"crl_urls,omitempty"`
	// CRLFiles (Optional) A predefined list of files pointing to CRLs. These lists will be checked for all client certificates.
	// The predefined CRLs will be loaded on startup
	// PEM and DER encoding are both supported
	CRLFiles []string `json:"crl_files,omitempty"`
	// TrustedSignatureCertsFiles (Optional) A predefined list of files of CA certificates which are trusted for CRL signing.
	// These certificates will be used to verify CRL signature if the CRL signature cert is not part of the client cert chain.
	// If the signature cert is part of the client cert chain there is no need to configure a certificate here.
	// PEM and DER encoding are both supported
	TrustedSignatureCertsFiles []string `json:"trusted_signature_certs_files,omitempty"`

	SignatureValidationModeParsed SignatureValidationMode `json:"-"`
	StorageTypeParsed             StorageType             `json:"-"`
	TrustedSignatureCerts         []*x509.Certificate     `json:"-"`
	UpdateIntervalParsed          time.Duration           `json:"-"`
}

type OCSPConfig struct {
	// DefaultCacheDuration The default time to cache OCSP responses (Optional) (Default: 0)
	// Valid time units are “ns”, “us” (or “µs”), “ms”, “s”, “m”, “h”
	// If the default time is zero no caching will be performed.
	DefaultCacheDuration string `json:"default_cache_duration,omitempty"`
	// TrustedResponderCertsFiles (Optional) A predefined list of files of CA certificates which are trusted to verify the OCSP response signature.
	// These certificates will be used to verify OCSP response signature if the ocsp response signature cert is not part of the client cert chain.
	// If the signature cert is part of the client cert chain there is no need to configure a certificate here.
	// PEM and DER encoding are both supported
	TrustedResponderCertsFiles []string `json:"trusted_responder_certs_files,omitempty"`
	// OCSPAIAStrict Configures if OCSP checking is mandatory to allow a connection if AIA is defined (Optional) (Default: false)
	// In strict mode it is required that if an OCSP server is defined inside AIA extension at least
	// one OCSP server defined can be contacted to check for revocation. Or a valid response of one of the OCSP server is inside the cache
	// If no OCSP server can be contacted and no cached response is present or the validation of the OCSP response signature failed connection is denied.
	OCSPAIAStrict bool `json:"ocsp_aia_strict,omitempty"`

	TrustedResponderCerts      []*x509.Certificate `json:"-"`
	DefaultCacheDurationParsed time.Duration       `json:"-"`
}
