package revocation

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"go.uber.org/zap"
	"os"
	"time"
)

const defaultCRLUpdateInterval = 30 * time.Minute

func ParseConfig(unmarshalledRevocationConfig *UnmarshalledRevocationConfig, logger *zap.Logger) (*ParsedRevocationConfig, error) {
	logger.Info("parsing caddy revocation validator config")
	var crlConfigParsed *config.CRLConfigParsed = nil
	var err error = nil
	if unmarshalledRevocationConfig.CRLConfig != nil {
		logger.Info("parsing crl config")
		crlConfigParsed, err = parseCRLConfig(unmarshalledRevocationConfig.CRLConfig)
		if err != nil {
			return nil, err
		}
	}

	var ocspConfigParsed *config.OCSPConfigParsed = &config.OCSPConfigParsed{
		TrustedResponderCerts:      make([]*x509.Certificate, 0),
		DefaultCacheDurationParsed: 0,
	}
	if unmarshalledRevocationConfig.OCSPConfig != nil {
		logger.Info("parsing ocsp config")
		ocspConfigParsed, err = parseOCSPConfig(unmarshalledRevocationConfig.OCSPConfig)
		if err != nil {
			return nil, err
		}
	}
	logger.Info("parsing mode")
	revocationModeParsed, err := parseMode(unmarshalledRevocationConfig)
	if err != nil {
		return nil, err
	}
	hash, err := calculateConfigHash(unmarshalledRevocationConfig.OCSPConfig, unmarshalledRevocationConfig.CRLConfig, unmarshalledRevocationConfig.Mode)
	if err != nil {
		return nil, err
	}
	parsedRevocationConfig := &ParsedRevocationConfig{revocationModeParsed, crlConfigParsed, ocspConfigParsed, hash}
	return parsedRevocationConfig, nil
}

func parseMode(cfg *UnmarshalledRevocationConfig) (config.RevocationCheckMode, error) {
	if len(cfg.Mode) > 0 {
		switch cfg.Mode {
		case "prefer_crl":
			return config.RevocationCheckModePreferCRL, nil
		case "prefer_ocsp":
			return config.RevocationCheckModePreferOCSP, nil
		case "ocsp_only":
			return config.RevocationCheckModeOCSPOnly, nil
		case "crl_only":
			return config.RevocationCheckModeCRLOnly, nil
		case "disabled":
			return config.RevocationCheckModeDisabled, nil
		default:
			return 0, fmt.Errorf("mode not recognized: %s", cfg.Mode)
		}
	} else {
		return config.RevocationCheckModePreferOCSP, nil
	}
}

func parseCDPConfig(cdpConfig *config.CDPConfig) (*config.CDPConfigParsed, error) {

	fetchModeParsed := config.CRLFetchModeActively
	if len(cdpConfig.CRLFetchMode) > 0 {
		switch cdpConfig.CRLFetchMode {
		case "fetch_actively":
			fetchModeParsed = config.CRLFetchModeActively
		case "fetch_background":
			fetchModeParsed = config.CRLFetchModeBackground
		default:
			return nil, fmt.Errorf("crl_fetch_mode not recognized: %s", cdpConfig.CRLFetchMode)
		}
	}
	return &config.CDPConfigParsed{fetchModeParsed, cdpConfig.CRLCDPStrict}, nil
}

func parseCRLConfig(crlConfig *config.CRLConfig) (*config.CRLConfigParsed, error) {

	var err error = nil
	signatureValidationMode, err := parseSignatureValidationMode(crlConfig)
	if err != nil {
		return nil, err
	}
	storageType, err := parseStorageType(crlConfig)
	if err != nil {
		return nil, err
	}
	updateInterval, err := parseUpdateInterval(crlConfig)
	if err != nil {
		return nil, err
	}
	trustedCrlSignatureCerts, err := parseTrustedCrlSignerCerts(crlConfig)
	if err != nil {
		return nil, err
	}

	cdpConfigParsed := &config.CDPConfigParsed{
		CRLFetchModeParsed: config.CRLFetchModeActively,
		CRLCDPStrict:       false,
	}

	if crlConfig.CDPConfig != nil {
		cdpConfigParsed, err = parseCDPConfig(crlConfig.CDPConfig)
		if err != nil {
			return nil, err
		}
	}

	crlConfigParsed := &config.CRLConfigParsed{signatureValidationMode, storageType, trustedCrlSignatureCerts, updateInterval, cdpConfigParsed, crlConfig.WorkDir, crlConfig.CRLUrls, crlConfig.CRLFiles}
	return crlConfigParsed, nil
}

func calculateConfigHash(ocspConfig *config.OCSPConfig, crlConfig *config.CRLConfig, mode string) (string, error) {
	ocspHash, err := calculateOcspConfigHash(ocspConfig)
	if err != nil {
		return "", err
	}

	crlHash, err := calculateCrlConfigHash(crlConfig)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, err = hash.Write([]byte(mode))
	if err != nil {
		return "", err
	}
	_, err = hash.Write([]byte(crlHash))
	if err != nil {
		return "", err
	}

	_, err = hash.Write([]byte(ocspHash))
	if err != nil {
		return "", err
	}
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum), nil
}
func calculateCrlConfigHash(cfg *config.CRLConfig) (string, error) {
	jsonData, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, err = hash.Write(jsonData)
	if err != nil {
		return "", err
	}
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum), nil
}

func calculateOcspConfigHash(cfg *config.OCSPConfig) (string, error) {
	jsonData, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, err = hash.Write(jsonData)
	if err != nil {
		return "", err
	}
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum), nil
}

func parseOCSPConfig(ocspConfig *config.OCSPConfig) (*config.OCSPConfigParsed, error) {

	defaultCacheDuration, err := parseDefaultCacheDuration(ocspConfig)
	if err != nil {
		return nil, err
	}
	trustedResponderCerts, err := parseTrustedOcspResponderCerts(ocspConfig)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &config.OCSPConfigParsed{trustedResponderCerts, defaultCacheDuration, ocspConfig.OCSPAIAStrict}, nil
}

func parseTrustedOcspResponderCerts(ocspConfig *config.OCSPConfig) ([]*x509.Certificate, error) {
	trustedResponderCerts := make([]*x509.Certificate, 0)
	for _, certFile := range ocspConfig.TrustedResponderCertsFiles {
		certificate, err := parseCertFromFile(certFile)
		if err != nil {
			return nil, err
		}
		trustedResponderCerts = append(trustedResponderCerts, certificate)
	}
	return trustedResponderCerts, nil
}

func parseDefaultCacheDuration(ocspConfig *config.OCSPConfig) (time.Duration, error) {
	if len(ocspConfig.DefaultCacheDuration) > 0 {
		return time.ParseDuration(ocspConfig.DefaultCacheDuration)
	} else {
		return time.Duration(0), nil
	}
}

func parseTrustedCrlSignerCerts(crlConfig *config.CRLConfig) ([]*x509.Certificate, error) {
	trustedSignatureCerts := make([]*x509.Certificate, 0)
	for _, certFile := range crlConfig.TrustedSignatureCertsFiles {
		certificate, err := parseCertFromFile(certFile)
		if err != nil {
			return nil, err
		}
		trustedSignatureCerts = append(trustedSignatureCerts, certificate)
	}
	return trustedSignatureCerts, nil
}

func parseCertFromFile(certFile string) (*x509.Certificate, error) {
	certBytes, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certBytes)
	if block == nil {
		return nil, fmt.Errorf("no CERTIFICATE pem block found in %s", certFile)
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate from file #{certFile} %v", err)
	}
	return certificate, nil
}

func parseSignatureValidationMode(crlCfg *config.CRLConfig) (config.SignatureValidationMode, error) {
	if len(crlCfg.SignatureValidationMode) > 0 {
		switch crlCfg.SignatureValidationMode {
		case "none":
			return config.SignatureValidationModeNone, nil
		case "verify_log":
			return config.SignatureValidationModeVerifyLog, nil
		case "verify":
			return config.SignatureValidationModeVerify, nil
		default:
			return 0, fmt.Errorf("signature_validation_mode not recognized: %s", crlCfg.SignatureValidationMode)
		}
	} else {
		return config.SignatureValidationModeVerify, nil
	}
}

func parseStorageType(crlCfg *config.CRLConfig) (config.StorageType, error) {
	if len(crlCfg.StorageType) > 0 {
		switch crlCfg.StorageType {
		case "memory":
			return config.Memory, nil
		case "disk":
			return config.Disk, nil
		default:
			return 0, fmt.Errorf("storage_type not recognized: %s", crlCfg.StorageType)
		}
	} else {
		return config.Disk, nil
	}
}

func parseUpdateInterval(config *config.CRLConfig) (time.Duration, error) {
	if len(config.UpdateInterval) > 0 {
		duration, err := time.ParseDuration(config.UpdateInterval)
		if err != nil {
			return 0, err
		}
		return duration, nil
	} else {
		return defaultCRLUpdateInterval, nil
	}
}
