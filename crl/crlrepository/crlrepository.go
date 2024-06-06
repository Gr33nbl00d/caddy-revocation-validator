package crlrepository

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/config"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/asn1parser"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlloader"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlstore"
	"go.uber.org/zap"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

type Repository struct {
	Factory           crlstore.Factory
	crlRepositoryLock *sync.RWMutex
	crlRepository     map[string]*Entry
	crlConfig         *config.CRLConfig
	logger            *zap.Logger
	crlLoaderFactory  crlloader.CRLLoaderFactory
	crlReader         crlreader.CRLReader
}

type Entry struct {
	entryLock                       *sync.RWMutex
	CRLLoader                       crlloader.CRLLoader
	CRLStore                        crlstore.CRLStore
	LastUpdateSignatureVerifyFailed bool
	LastUpdateSignature             *crlreader.CRLReadResult
	Loaded                          bool
	//only used temporary
	Chains *core.CertificateChains
}

func NewCRLRepository(logger *zap.Logger, crlConfig *config.CRLConfig, storeType crlstore.StoreType) (error, *Repository) {
	factory, err := crlstore.CreateStoreFactory(storeType, crlConfig.WorkDir, logger)
	if err != nil {
		return err, nil
	}
	repository := Repository{factory,
		&sync.RWMutex{},
		make(map[string]*Entry),
		crlConfig,
		logger,
		crlloader.DefaultCRLLoaderFactory{},
		crlreader.StreamingCRLFileReader{},
	}
	return nil, &repository
}

func (R *Repository) AddCRL(crlLocations *core.CRLLocations, chains *core.CertificateChains) (bool, error) {
	loader, err := R.crlLoaderFactory.CreatePreferredCrlLoader(crlLocations, R.logger)
	if err != nil {
		return false, err
	}
	identifier, err := loader.GetCRLLocationIdentifier()
	if err != nil {
		return false, fmt.Errorf("could not calculate crl location identifier: %v", err)
	}
	entry, crlAdded, err := R.getOrAddEntry(identifier, loader, chains)
	if err != nil {
		return false, err
	}
	if R.crlConfig.CDPConfig.CRLFetchModeParsed == config.CRLFetchModeActively {
		if R.isEntryLoaded(entry) == false {
			return crlAdded, R.loadActively(entry, chains, crlLocations)
		}
	}

	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	if entry.LastUpdateSignatureVerifyFailed {
		//check if the chain contains a new valid signing cert
		R.tryUpdateSignatureCertFromChain(entry, chains)
	}
	return crlAdded, nil
}

func (R *Repository) isEntryLoaded(entry *Entry) bool {
	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	return entry.Loaded
}

func (R *Repository) getOrAddEntry(identifier string, loader crlloader.CRLLoader, chains *core.CertificateChains) (*Entry, bool, error) {
	R.crlRepositoryLock.Lock()
	defer R.crlRepositoryLock.Unlock()
	entry := R.crlRepository[identifier]
	if entry == nil {
		entry, err := R.addNewEmptyEntry(loader, identifier, chains)
		if err != nil {
			//crl was not added because of error
			return entry, false, err
		}
		//crl was added
		return entry, true, nil
	} else {
		//crl already existed
		return entry, false, nil
	}
}

func (R *Repository) tryUpdateSignatureCertFromChain(entry *Entry, chains *core.CertificateChains) {
	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	//check if no other thread updated the signature in meantime
	if entry.LastUpdateSignatureVerifyFailed == true {
		signature, err := verifyCRLSignature(entry.LastUpdateSignature, chains)
		if err != nil {
			R.logger.Warn("unable to find updated crl signature cert", zap.Error(err))
			return
		}
		err = entry.CRLStore.UpdateSignatureCertificate(signature)
		if err != nil {
			R.logger.Warn("unable to update crl signature cert", zap.Error(err))
			return
		}
		entry.LastUpdateSignatureVerifyFailed = false
	}
}

func (R *Repository) loadCRL(entry *Entry, chains *core.CertificateChains) (err error) {
	R.logger.Debug("loading crl", zap.String("crl", entry.CRLLoader.GetDescription()))
	tempFileName, err := R.createTempFile()
	if err != nil {
		return err
	}
	defer utils.CloseWithErrorHandling(func() error { return os.Remove(tempFileName) })
	err = entry.CRLLoader.LoadCRL(tempFileName)
	if err != nil {
		return err
	}
	var processor = crlstore.CRLPersisterProcessor{CRLStore: entry.CRLStore}
	result, err := R.crlReader.ReadCRL(processor, tempFileName)
	if err != nil {
		return err
	}
	if R.crlConfig.SignatureValidationModeParsed != config.SignatureValidationModeNone {
		signatureCert, err := verifyCRLSignature(result, chains)
		if err != nil {
			R.logger.Warn("could not validate signature of crl", zap.String("crl", entry.CRLLoader.GetDescription()))
			if R.crlConfig.SignatureValidationModeParsed == config.SignatureValidationModeVerify {
				return err
			}
		} else {
			R.logger.Debug("signature of crl validated successfully", zap.String("crl", entry.CRLLoader.GetDescription()))
			err = processor.UpdateSignatureCertificate(signatureCert)
			if err != nil {
				return err
			}
			R.logger.Debug("crl loaded successfully", zap.String("crl", entry.CRLLoader.GetDescription()))
		}
	}
	entry.Loaded = true
	entry.Chains = nil
	return nil
}

func (R *Repository) addNewEmptyEntry(loader crlloader.CRLLoader, identifier string, chains *core.CertificateChains) (*Entry, error) {
	store, err := R.Factory.CreateStore(identifier, false)
	if err != nil {
		return nil, err
	}
	newEntry := Entry{
		CRLLoader: loader,
		CRLStore:  store,
		Chains:    chains,
		entryLock: &sync.RWMutex{},
	}
	//if this is persistent store it might be present already
	if store.IsEmpty() == false {
		newEntry.Loaded = true
	}
	R.crlRepository[identifier] = &newEntry
	return &newEntry, nil
}

func (R *Repository) createTempFile() (string, error) {
	tempFile, err := os.CreateTemp(R.crlConfig.WorkDir, "crl_*_tmp")
	defer utils.CloseWithErrorHandling(tempFile.Close)
	if err != nil {
		return "", err
	}
	tempFileName := tempFile.Name()
	return tempFileName, nil
}

func (R *Repository) IsRevoked(certificate *x509.Certificate, locations *core.CRLLocations) (*core.RevocationStatus, error) {
	if locations != nil {
		loader, err := R.crlLoaderFactory.CreatePreferredCrlLoader(locations, R.logger)
		if err != nil {
			return nil, err
		}
		identifier, err := loader.GetCRLLocationIdentifier()
		if err != nil {
			return nil, err
		}
		//In strict mode enforce CDP CRL is loaded otherwise abort
		if R.crlConfig.CDPConfig.CRLCDPStrict && R.isEntryPresentAndLoaded(identifier) == false {
			return nil, fmt.Errorf("CRL defined in CDP was not loaded")
		}
	}
	identifiers := R.getCurrentIdentifiers()
	for _, identifier := range identifiers {
		status, err := R.checkCrl(certificate, identifier)
		if err != nil {
			return nil, err
		}
		if status.Revoked {
			return status, nil
		}
	}
	return &core.RevocationStatus{}, nil
}

func (R *Repository) checkCrl(certificate *x509.Certificate, identifier string) (*core.RevocationStatus, error) {
	issuerRDNSequence, err := asn1parser.ParseIssuerRDNSequence(certificate)
	if err != nil {
		return nil, err
	}
	repositoryEntry := R.getEntrySync(identifier)
	if repositoryEntry != nil {
		repositoryEntry.entryLock.RLock()
		defer repositoryEntry.entryLock.RUnlock()
		if repositoryEntry.Loaded {
			status, err := repositoryEntry.CRLStore.GetCertRevocationStatus(issuerRDNSequence, certificate.SerialNumber)
			if err != nil {
				return nil, fmt.Errorf("could not get revocation status from repository: %v", err)
			}
			if status.Revoked {
				return status, nil
			}
		}
	}
	return &core.RevocationStatus{}, nil
}

func (R *Repository) getCurrentIdentifiers() []string {
	R.crlRepositoryLock.RLock()
	defer R.crlRepositoryLock.RUnlock()
	keys := make([]string, 0, len(R.crlRepository))
	for k := range R.crlRepository {
		keys = append(keys, k)
	}
	return keys
}

func (R *Repository) UpdateCRLs() {
	R.logger.Debug("starting update of CRLs")
	identifiers := R.getCurrentIdentifiers()
	for _, k := range identifiers {
		err := R.updateCRL(k)
		if err != nil {
			R.logger.Warn("failed to update CRL", zap.Error(err))
		}
	}
	R.logger.Debug("Update of CRLs finished")
}

func (R *Repository) updateCRL(identifier string) error {
	entry := R.getEntrySync(identifier)
	if entry != nil {
		R.logger.Debug("updating crl from " + entry.CRLLoader.GetDescription())
		if R.isEntryLoaded(entry) == false {
			return R.loadCRL(entry, entry.Chains)
		} else {
			return R.updateCrlEntry(entry, nil)
		}
	}
	return nil
}

func (R *Repository) updateCrlEntry(entry *Entry, newChains *core.CertificateChains) (err error) {
	R.logger.Info("updating crl " + entry.CRLLoader.GetDescription())
	var store crlstore.CRLStore
	tempFileName, err := R.createTempFile()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && store != nil {
			store.Close()
			err2 := store.Delete()
			if err2 != nil {
				R.logger.Warn("failed to delete database", zap.Error(err2))
			}
		}
	}()
	defer utils.CloseWithErrorHandling(func() error { return os.Remove(tempFileName) })

	var chains = newChains

	points, storedChains, err := R.getCrlUpdateInformation(entry, err)
	if err != nil {
		return err
	}
	if chains == nil {
		chains = storedChains
	}
	loader, err := R.crlLoaderFactory.CreatePreferredCrlLoader(points, R.logger)
	if err != nil {
		return err
	}
	R.logger.Info("loading crl " + entry.CRLLoader.GetDescription())
	err = loader.LoadCRL(tempFileName)
	if err != nil {
		return err
	}
	identifier, err := loader.GetCRLLocationIdentifier()
	if err != nil {
		return err
	}
	store, err = R.Factory.CreateStore(identifier, true)
	if err != nil {
		return err
	}

	var processor = crlstore.CRLPersisterProcessor{CRLStore: store}
	R.logger.Info("parsing crl loaded from " + entry.CRLLoader.GetDescription())
	err = processor.UpdateCRLLocations(points)
	if err != nil {
		return err
	}

	result, err := R.crlReader.ReadCRL(processor, tempFileName)
	if err != nil {
		return err
	}
	R.logger.Info("verify crl signature of crl " + entry.CRLLoader.GetDescription())
	signatureCert, err := verifyCRLSignature(result, chains)
	if err != nil {
		R.setLastSignatureVerifyFailed(entry, result)
		return err
	} else {
		R.resetLastSignatureVerifyFailed(entry)
	}

	err = processor.UpdateSignatureCertificate(signatureCert)
	if err != nil {
		return err
	}

	err = R.updateEntry(entry, err, store)
	if err != nil {
		R.deleteEntrySync(identifier)
		return err
	}
	R.logger.Info("finished updating crl " + entry.CRLLoader.GetDescription())
	return nil
}

func (R *Repository) resetLastSignatureVerifyFailed(entry *Entry) {
	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	entry.LastUpdateSignatureVerifyFailed = false
	entry.LastUpdateSignature = nil
}

func (R *Repository) setLastSignatureVerifyFailed(entry *Entry, result *crlreader.CRLReadResult) {
	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	entry.LastUpdateSignatureVerifyFailed = true
	entry.LastUpdateSignature = result
}

func (R *Repository) getCrlUpdateInformation(entry *Entry, err error) (*core.CRLLocations, *core.CertificateChains, error) {
	entry.entryLock.RLock()
	defer entry.entryLock.RUnlock()
	oldStore := entry.CRLStore
	points, err := oldStore.GetCRLLocations()
	if err != nil {
		return nil, nil, err
	}
	chains, err := R.getStoredCertAsChain(oldStore)
	if err != nil {
		return nil, nil, err
	}
	return points, chains, nil
}

func (R *Repository) updateEntry(entry *Entry, err error, store crlstore.CRLStore) error {
	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	err = entry.CRLStore.Update(store)
	if err != nil {
		entry.CRLStore.Close()
		//mark as empty in case someone already acquired the entry and waits for a lock
		entry.CRLStore = nil
	}
	return err
}

func (R *Repository) getStoredCertAsChain(oldStore crlstore.CRLStore) (*core.CertificateChains, error) {
	chains := &core.CertificateChains{
		CertificateChainList: make([]core.CertificateChain, 0),
	}

	cert, err := oldStore.GetCRLSignatureCert()
	if err != nil {
		return chains, nil
	}

	chains = core.NewCertificateChainsFromEntry(cert)
	return chains, nil
}

func verifyCRLSignature(result *crlreader.CRLReadResult, chains *core.CertificateChains) (*core.CertificateChainEntry, error) {
	certCandidates, err := core.FindCertificateIssuerCandidates(result.Issuer, result.CRLExtensions, result.HashAndVerifyStrategy.VerifyStrategy.GetAlgorithmID(), chains)
	if err != nil {
		return nil, err
	}
	if len(certCandidates) == 0 {
		return nil, errors.New("can not find CRL issuer certificate")
	}

	var signatureCert *core.CertificateChainEntry
	crlVerified := false
	for _, certCandidate := range certCandidates {
		strategies := result.HashAndVerifyStrategy
		err := strategies.VerifyStrategy.VerifySignature(strategies.HashStrategy, certCandidate.Certificate.PublicKey, result.CalculatedSignature, result.Signature.Bytes)
		if err == nil {
			crlVerified = true
			signatureCert = certCandidate
			break
		}
	}
	if crlVerified == false {
		return nil, errors.New("can not verify CRL signature with given issuer certificates")
	}
	return signatureCert, nil
}

func (R *Repository) DeleteTempFilesIfExist() {
	repoDirBasePath, err := os.Stat(R.crlConfig.WorkDir)
	if err != nil {
		R.logger.Warn(fmt.Sprintf("Error while cleaning temp directory %s: %v", R.crlConfig.WorkDir, err))
	}
	err = filepath.Walk(R.crlConfig.WorkDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !os.SameFile(info, repoDirBasePath) {
			R.deleteIfTempFileOrDir(path, info)
		}
		if info.IsDir() && !os.SameFile(info, repoDirBasePath) {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		R.logger.Warn(fmt.Sprintf("Error while cleaning temp directory %s: %v", R.crlConfig.WorkDir, err))
	}
}

func (R *Repository) deleteIfTempFileOrDir(path string, info os.FileInfo) {
	matchString, err := regexp.MatchString("^crl_.*\\_tmp$", info.Name())
	if err != nil {
		//this can only happen if regex pattern is wrong
		panic(err)
	}
	if matchString {
		err := os.RemoveAll(path)
		if err != nil {
			R.logger.Warn(fmt.Sprintf("Error while removing temp file %s: %v", path, err))
		}
	}
}

func (R *Repository) getEntrySync(identifier string) *Entry {
	R.crlRepositoryLock.RLock()
	defer R.crlRepositoryLock.RUnlock()
	return R.crlRepository[identifier]
}

func (R *Repository) deleteEntrySync(identifier string) {
	R.crlRepositoryLock.Lock()
	defer R.crlRepositoryLock.Unlock()
	delete(R.crlRepository, identifier)
}

func (R *Repository) isEntryPresentAndLoaded(identifier string) bool {
	entrySync := R.getEntrySync(identifier)
	if entrySync != nil {
		entrySync.entryLock.RLock()
		defer entrySync.entryLock.RUnlock()
		return entrySync.Loaded
	}
	return false
}

func (R *Repository) loadActively(entry *Entry, chains *core.CertificateChains, crlLocations *core.CRLLocations) error {
	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	//check again after getting write lock if entry is still not loaded
	if entry.Loaded == false {
		err := entry.CRLStore.UpdateCRLLocations(crlLocations)
		if err != nil {
			return err
		}
		return R.loadCRL(entry, chains)
	}
	return nil
}

func (R *Repository) UpdateCRL(crlLocations *core.CRLLocations, chains *core.CertificateChains) error {
	loader, err := R.crlLoaderFactory.CreatePreferredCrlLoader(crlLocations, R.logger)
	if err != nil {
		return err
	}
	identifier, err := loader.GetCRLLocationIdentifier()
	if err != nil {
		return fmt.Errorf("could not calculate crl location identifier: %v", err)
	}
	entry := R.getEntrySync(identifier)
	if entry != nil {
		err := R.updateCrlEntry(entry, chains)
		if err != nil {
			return err
		}
	}
	return nil
}

func (R *Repository) Close() {
	R.crlRepositoryLock.Lock()
	defer R.crlRepositoryLock.Unlock()
	for id, entry := range R.crlRepository {
		R.closeRepositoryEntry(entry, id)
	}
}

func (R *Repository) closeRepositoryEntry(entry *Entry, id string) {
	entry.entryLock.Lock()
	defer entry.entryLock.Unlock()
	entry.CRLStore.Close()
	R.crlRepository[id] = nil
}
