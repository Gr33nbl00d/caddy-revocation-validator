package revocation

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"io/ioutil"
	"time"
)

const defaultCRLUpdateInterval = 30 * time.Minute

func ParseConfig(certRevocationValidator *CertRevocationValidator) error {
	certRevocationValidator.logger.Info("parsing caddy revocation validator config")
	if certRevocationValidator.CRLConfig != nil {
		certRevocationValidator.logger.Info("parsing crl config")
		err := parseCRLConfig(certRevocationValidator.CRLConfig)
		if err != nil {
			return err
		}
	}

	if certRevocationValidator.OCSPConfig != nil {
		certRevocationValidator.logger.Info("parsing ocsp config")
		err := parseOCSPConfig(certRevocationValidator.OCSPConfig)
		if err != nil {
			return err
		}
	} else {
		certRevocationValidator.OCSPConfig = &config.OCSPConfig{
			TrustedResponderCertsFiles: make([]string, 0),
			DefaultCacheDuration:       "",
			TrustedResponderCerts:      make([]*x509.Certificate, 0),
			DefaultCacheDurationParsed: 0,
		}
	}
	certRevocationValidator.logger.Info("parsing mode")
	err := parseMode(certRevocationValidator)
	if err != nil {
		return err
	}
	return nil
}

func parseMode(revocationValidator *CertRevocationValidator) error {
	if len(revocationValidator.Mode) > 0 {
		switch revocationValidator.Mode {
		case "prefer_crl":
			revocationValidator.ModeParsed = config.RevocationCheckModePreferCRL
		case "prefer_ocsp":
			revocationValidator.ModeParsed = config.RevocationCheckModePreferOCSP
		case "ocsp_only":
			revocationValidator.ModeParsed = config.RevocationCheckModeOCSPOnly
		case "crl_only":
			revocationValidator.ModeParsed = config.RevocationCheckModeCRLOnly
		case "disabled":
			revocationValidator.ModeParsed = config.RevocationCheckModeDisabled
		default:
			return fmt.Errorf("mode not recognized: %s", revocationValidator.Mode)
		}
	} else {
		revocationValidator.ModeParsed = config.RevocationCheckModePreferOCSP
	}
	return nil

}

func parseCDPConfig(cdpConfig *config.CDPConfig) error {
	if len(cdpConfig.CRLFetchMode) > 0 {
		switch cdpConfig.CRLFetchMode {
		case "fetch_actively":
			cdpConfig.CRLFetchModeParsed = config.CRLFetchModeActively
		case "fetch_background":
			cdpConfig.CRLFetchModeParsed = config.CRLFetchModeBackground
		default:
			return fmt.Errorf("crl_fetch_mode not recognized: %s", cdpConfig.CRLFetchMode)
		}
	} else {
		cdpConfig.CRLFetchModeParsed = config.CRLFetchModeActively
	}
	return nil
}

func parseCRLConfig(crlConfig *config.CRLConfig) error {
	err := parseSignatureValidationMode(crlConfig)
	if err != nil {
		return err
	}
	err = parseStorageType(crlConfig)
	if err != nil {
		return err
	}
	err = parseUpdateInterval(crlConfig)
	if err != nil {
		return err
	}
	err = parseTrustedCrlSignerCerts(crlConfig)
	if err != nil {
		return err
	}
	if crlConfig.CDPConfig != nil {
		err := parseCDPConfig(crlConfig.CDPConfig)
		if err != nil {
			return err
		}
	} else {
		crlConfig.CDPConfig = &config.CDPConfig{
			CRLFetchMode:       "",
			CRLFetchModeParsed: config.CRLFetchModeActively,
			CRLCDPStrict:       false,
		}
	}
	return nil
}

func parseOCSPConfig(ocspConfig *config.OCSPConfig) error {
	err := parseDefaultCacheDuration(ocspConfig)
	if err != nil {
		return err
	}
	err = parseTrustedOcspResponderCerts(ocspConfig)
	if err != nil {
		return err
	}
	return nil
}

func parseTrustedOcspResponderCerts(ocspConfig *config.OCSPConfig) error {
	ocspConfig.TrustedResponderCerts = make([]*x509.Certificate, 0)
	for _, certFile := range ocspConfig.TrustedResponderCertsFiles {
		certificate, err := parseCertFromFile(certFile)
		if err != nil {
			return err
		}
		ocspConfig.TrustedResponderCerts = append(ocspConfig.TrustedResponderCerts, certificate)
	}
	return nil
}

func parseDefaultCacheDuration(ocspConfig *config.OCSPConfig) error {
	if len(ocspConfig.DefaultCacheDuration) > 0 {
		duration, err := time.ParseDuration(ocspConfig.DefaultCacheDuration)
		if err != nil {
			return err
		}
		ocspConfig.DefaultCacheDurationParsed = duration
	} else {
		ocspConfig.DefaultCacheDurationParsed = time.Duration(0)
	}
	return nil
}

func parseTrustedCrlSignerCerts(crlConfig *config.CRLConfig) error {
	crlConfig.TrustedSignatureCerts = make([]*x509.Certificate, 0)
	for _, certFile := range crlConfig.TrustedSignatureCertsFiles {
		certificate, err := parseCertFromFile(certFile)
		if err != nil {
			return err
		}
		crlConfig.TrustedSignatureCerts = append(crlConfig.TrustedSignatureCerts, certificate)
	}
	return nil
}

func parseCertFromFile(certFile string) (*x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("no CERTIFICATE pem block found in %s", certFile)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

func parseSignatureValidationMode(crlCfg *config.CRLConfig) error {
	if len(crlCfg.SignatureValidationMode) > 0 {
		switch crlCfg.SignatureValidationMode {
		case "none":
			crlCfg.SignatureValidationModeParsed = config.SignatureValidationModeNone
		case "verify_log":
			crlCfg.SignatureValidationModeParsed = config.SignatureValidationModeVerifyLog
		case "verify":
			crlCfg.SignatureValidationModeParsed = config.SignatureValidationModeVerify
		default:
			return fmt.Errorf("signature_validation_mode not recognized: %s", crlCfg.SignatureValidationMode)
		}
	} else {
		crlCfg.SignatureValidationModeParsed = config.SignatureValidationModeVerify
	}
	return nil
}

func parseStorageType(crlCfg *config.CRLConfig) error {
	if len(crlCfg.StorageType) > 0 {
		switch crlCfg.StorageType {
		case "memory":
			crlCfg.StorageTypeParsed = config.Memory
		case "disk":
			crlCfg.StorageTypeParsed = config.Disk
		default:
			return fmt.Errorf("storage_type not recognized: %s", crlCfg.StorageType)
		}
	} else {
		crlCfg.StorageTypeParsed = config.Disk
	}
	return nil
}

func parseUpdateInterval(config *config.CRLConfig) error {
	if len(config.UpdateInterval) > 0 {
		duration, err := time.ParseDuration(config.UpdateInterval)
		if err != nil {
			return err
		}
		config.UpdateIntervalParsed = duration
	} else {
		config.UpdateIntervalParsed = defaultCRLUpdateInterval
	}
	return nil
}
