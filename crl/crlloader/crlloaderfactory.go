package crlloader

import (
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"go.uber.org/zap"
	"strings"
)

type CRLLoaderFactory interface {
	CreatePreferredCrlLoader(crlLocations *core.CRLLocations, logger *zap.Logger) (CRLLoader, error)
}
type DefaultCRLLoaderFactory struct {
}

func (R DefaultCRLLoaderFactory) CreatePreferredCrlLoader(crlLocations *core.CRLLocations, logger *zap.Logger) (CRLLoader, error) {

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
		return nil, fmt.Errorf("no suitable crl loader found")
	}
	return MultiSchemesCRLLoader{
		Loaders: cdpLoaders,
		Logger:  logger,
	}, nil
}
