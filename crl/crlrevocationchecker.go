package crl

import (
	"crypto/x509"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlrepository"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlstore"
	"go.uber.org/zap"
	"log"
	"runtime/debug"
	"sync"
	"time"
)

type CRLRevocationChecker struct {
	crlRepository   *crlrepository.Repository
	crlConfig       *config.CRLConfigParsed
	logger          *zap.Logger
	crlUpdateTicker *time.Ticker
	crlUpdateStop   chan struct{}
}

func (c *CRLRevocationChecker) IsRevoked(clientCertificate *x509.Certificate, verifiedChains [][]*x509.Certificate) (*core.RevocationStatus, error) {
	//TODO verify if crl if defined in cdp is fresh otherwise might deny connnection with some grace time see
	//TODO See RFC 5019 Section 4 - Ensuring an OCSPResponse Is Fresh
	var locations *core.CRLLocations

	if len(clientCertificate.CRLDistributionPoints) > 0 {
		chains := core.NewCertificateChains(verifiedChains, c.crlConfig.TrustedSignatureCerts)
		locations = &core.CRLLocations{CRLDistributionPoints: clientCertificate.CRLDistributionPoints}
		added, err := c.crlRepository.AddCRL(locations, chains)
		if err != nil {
			c.logger.Warn("Failed to add CRL from CDP", zap.Strings("cdp", clientCertificate.CRLDistributionPoints), zap.Error(err))
		} else {
			if added && c.crlConfig.CDPConfigParsed.CRLFetchModeParsed == config.CRLFetchModeBackground {
				go c.updateCRLs(true)
			}
		}

	}

	revoked, err := c.crlRepository.IsRevoked(clientCertificate, locations)
	return revoked, err
}

func (c *CRLRevocationChecker) Provision(crlConfig *config.CRLConfigParsed, logger *zap.Logger, configHash string) error {
	var err error = nil
	c.crlConfig = crlConfig
	c.logger = logger
	storeType := crlstore.Map
	if crlConfig.StorageTypeParsed == config.Disk {
		storeType = crlstore.LevelDB
	}
	logger.Info("creating crl repository of type " + crlstore.StoreTypeToString(storeType))
	err, c.crlRepository = crlrepository.NewCRLRepository(c.logger.Named("revocation"), crlConfig, storeType, configHash)
	if err != nil {
		return err
	}
	c.crlRepository.DeleteTempFilesIfExist()

	logger.Info("creating crl certificate chains")
	chains := core.NewCertificateChains(nil, crlConfig.TrustedSignatureCerts)
	logger.Info("adding crl entries from crl_urls config")
	err = c.addCrlUrlsFromConfig(chains)
	if err != nil {
		return err
	}
	logger.Info("adding crl entries from crl_files config")
	err = c.addCrlFilesFromConfig(chains)
	if err != nil {
		return err
	}
	logger.Info("Initializing CRL update ticker")
	c.initCRLUpdateTicker()
	return nil
}

func (c *CRLRevocationChecker) Cleanup() error {
	if c.crlRepository != nil {
		c.crlRepository.Close()
	}

	if c.crlUpdateTicker != nil {
		c.crlUpdateTicker.Stop()
	}
	return nil
}
func (c *CRLRevocationChecker) addCrlUrlsFromConfig(chains *core.CertificateChains) error {
	for _, crlUrl := range c.crlConfig.CRLUrls {
		crlLocations := core.CRLLocations{
			CRLUrl: crlUrl,
		}
		_, err := c.crlRepository.AddCRL(&crlLocations, chains)
		if err != nil {
			return err
		}
		//update in case chains have changed
		c.logger.Info("Updating crl from location " + crlUrl)
		err = c.crlRepository.UpdateCRL(&crlLocations, chains)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CRLRevocationChecker) addCrlFilesFromConfig(chains *core.CertificateChains) error {
	for _, crlFile := range c.crlConfig.CRLFiles {
		crlLocations := core.CRLLocations{
			CRLFile: crlFile,
		}
		_, err := c.crlRepository.AddCRL(&crlLocations, chains)
		if err != nil {
			return err
		}
		//update in case chains have changed
		c.logger.Info("Updating crl from location " + crlFile)
		err = c.crlRepository.UpdateCRL(&crlLocations, chains)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *CRLRevocationChecker) initCRLUpdateTicker() {
	parsed := c.crlConfig.UpdateIntervalParsed
	c.crlUpdateTicker = time.NewTicker(parsed)
	c.crlUpdateStop = make(chan struct{})
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("[PANIC] crl updater: %v\n%s", err, debug.Stack())
			}
		}()
		c.updateCRLs(false)
		for {
			select {
			case <-c.crlUpdateStop:
				return
			case <-c.crlUpdateTicker.C:
				go c.updateCRLs(false)
			}
		}
	}()

}
func (c *CRLRevocationChecker) updateCRLs(forceUpdate bool) {
	crlUpdateMutex.Lock()
	defer crlUpdateMutex.Unlock()

	// If crl update was recently done, don't do it again for now. Although the ticker
	// drops missed ticks for us, config reloads discard the old ticker and replace it
	// with a new one, possibly invoking a cleaning to happen again too soon.
	// (We divide the interval by 2 because the crl update takes non-zero time,
	// and we don't want to skip crl updates if we don't have to; whereas if a crl update
	// took the entire interval, we'd probably want to skip the next one, so we aren't
	// constantly updating. This allows crl updates to take up to half the interval's
	// duration before we decide to skip the next one.)
	if !forceUpdate && c.updateWasRecentlyFinished() {
		return
	}
	defer func() {
		// mark when crl update was last finished
		lastCrlUpdateFinishTime = time.Now()
	}()

	c.crlRepository.UpdateCRLs()
}

func (c *CRLRevocationChecker) updateWasRecentlyFinished() bool {
	return !lastCrlUpdateFinishTime.IsZero() && (time.Since(lastCrlUpdateFinishTime) < c.crlConfig.UpdateIntervalParsed/2)
}

var (
	crlUpdateMutex          sync.Mutex
	lastCrlUpdateFinishTime time.Time
)
