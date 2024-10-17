package revocation

import (
	"crypto/x509"
	"errors"
	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"sync"
)

type RevocationCheckerEntry struct {
	RevocationChecker      *RevocationChecker
	usageCount             int
	ParsedRevocationConfig *ParsedRevocationConfig
}

func (e *RevocationCheckerEntry) IncreaseUsageCount() int {
	e.usageCount++
	return e.usageCount
}

func (e *RevocationCheckerEntry) DecreaseUsageCount() int {
	e.usageCount--
	return e.usageCount
}

type RevocationCheckerRepository struct {
	crlRevocationCheckerRepository map[string]*RevocationCheckerEntry
	repositoryMutex                *sync.RWMutex
}

func (c *RevocationCheckerRepository) Provision(ctx caddy.Context, logger *zap.Logger, config *ParsedRevocationConfig) error {
	c.repositoryMutex.Lock()
	defer c.repositoryMutex.Unlock()
	entry := c.crlRevocationCheckerRepository[config.ConfigHash]
	if entry == nil {
		logger.Info("starting provision of revocation config id: " + config.ConfigHash)
		checker := &RevocationChecker{}
		err := checker.Provision(ctx, logger, config)
		if err != nil {
			return err
		}
		entry = &RevocationCheckerEntry{checker, 0, config}
		c.crlRevocationCheckerRepository[config.ConfigHash] = entry
	}
	entry.IncreaseUsageCount()
	return nil
}

func (c *RevocationCheckerRepository) Cleanup(config *ParsedRevocationConfig) error {
	c.repositoryMutex.Lock()
	defer c.repositoryMutex.Unlock()
	entry := c.crlRevocationCheckerRepository[config.ConfigHash]
	if entry != nil {
		count := entry.DecreaseUsageCount()
		if count == 0 {
			err := entry.RevocationChecker.Cleanup()
			if err != nil {
				return err
			}
			c.crlRevocationCheckerRepository[config.ConfigHash] = nil
		}
		//todo cleanup of unneded directories, In case config hash is changed directory stays forever
		//but this might be problematic because it might be just a temporary change for example temp disable the checking
		//suggestion1: allow option to configure if stores should always be recreated on server start and can therefore be deleted during cleanup
		//suggestion2: allow to define an unused store time delay (if the files of the leveldb are older than x days not been updated you can delete it)
	}
	return nil
}

func (c *RevocationCheckerRepository) VerifyClientCertificate(config *ParsedRevocationConfig, certs [][]byte, chains [][]*x509.Certificate) error {
	entry := c.getEntrySynced(config)
	if entry == nil {
		return errors.New("invalid state no RevocationCheckRepository found")
	}
	return entry.RevocationChecker.VerifyClientCertificate(certs, chains)
}

func (c *RevocationCheckerRepository) getEntrySynced(config *ParsedRevocationConfig) *RevocationCheckerEntry {
	c.repositoryMutex.RLock()
	defer c.repositoryMutex.RUnlock()
	entry := c.crlRevocationCheckerRepository[config.ConfigHash]
	return entry
}

var RevocationCheckerRepositoryInstance *RevocationCheckerRepository = &RevocationCheckerRepository{make(map[string]*RevocationCheckerEntry), &sync.RWMutex{}}
