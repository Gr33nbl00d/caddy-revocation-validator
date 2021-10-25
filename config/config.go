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
	CRLFetchMode       string       `json:"crl_fetch_mode,omitempty"`
	CRLCDPStrict       bool         `json:"crl_cdp_strict,omitempty"`
	CRLFetchModeParsed CRLFetchMode `json:"-"`
}

type CRLConfig struct {
	WorkDir                       string                  `json:"work_dir"`
	CDPConfig                     *CDPConfig              `json:"cdp_config,omitempty"`
	StorageType                   string                  `json:"storage_type,omitempty"`
	UpdateInterval                string                  `json:"update_interval,omitempty"`
	SignatureValidationMode       string                  `json:"signature_validation_mode,omitempty"`
	CRLUrls                       []string                `json:"crl_urls,omitempty"`
	CRLFiles                      []string                `json:"crl_files,omitempty"`
	TrustedSignatureCertsFiles    []string                `json:"trusted_signature_certs_files,omitempty"`
	SignatureValidationModeParsed SignatureValidationMode `json:"-"`
	StorageTypeParsed             StorageType             `json:"-"`
	TrustedSignatureCerts         []*x509.Certificate     `json:"-"`
	UpdateIntervalParsed          time.Duration           `json:"-"`
}

type OCSPConfig struct {
	DefaultCacheDuration       string              `json:"default_cache_duration,omitempty"`
	TrustedResponderCertsFiles []string            `json:"trusted_responder_certs_files,omitempty"`
	OCSPAIAStrict              bool                `json:"ocsp_aia_strict,omitempty"`
	TrustedResponderCerts      []*x509.Certificate `json:"-"`
	DefaultCacheDurationParsed time.Duration       `json:"-"`
}
