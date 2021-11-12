package crlloader

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"go.uber.org/zap"
	"strings"
	"time"
)

type CRLLoader interface {
	LoadCRL(filePath string) error
	GetCRLLocationIdentifier() (string, error)
	GetDescription() string
}

const CRLLoaderRetryCount = 5
const CRLLoaderRetryDelay = 500 * time.Millisecond

func calculateHashHexString(normalizedUrl string) string {
	hash := sha256.New()
	hash.Write([]byte(normalizedUrl))
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum)
}

func CreatePreferredCrlLoader(crlLocations *core.CRLLocations, logger *zap.Logger) (CRLLoader, error) {

	if len(crlLocations.CRLUrl) > 0 {
		return URLLoader{crlLocations.CRLUrl, logger}, nil
	}
	if len(crlLocations.CRLFile) > 0 {
		return FileLoader{crlLocations.CRLFile, logger}, nil
	}
	cdpLoaders := make([]CRLLoader, 0)
	for _, cdp := range crlLocations.CRLDistributionPoints {
		//todo might add support for LDAP
		if strings.HasPrefix(strings.ToLower(cdp), "http") {
			cdpLoaders = append(cdpLoaders, URLLoader{cdp, logger})
		} else {
			logger.Warn("unsupported CDP Location Scheme", zap.String("location", cdp))
		}
	}
	if len(cdpLoaders) == 0 {
		return nil, fmt.Errorf("not suitable crl loader found")
	}
	return MultiSchemesCRLLoader{
		Loaders: cdpLoaders,
		Logger:  logger,
	}, nil
}
