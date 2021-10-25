package crlstore

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/gr33nbl00d/caddy-tls-clr/core"
	"github.com/gr33nbl00d/caddy-tls-clr/core/hashing"
	"github.com/gr33nbl00d/caddy-tls-clr/core/utils"
	"github.com/gr33nbl00d/caddy-tls-clr/crl/crlreader"
	"github.com/syndtr/goleveldb/leveldb"
	"go.uber.org/zap"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type LevelDbStore struct {
	Db          *leveldb.DB
	Serializer  Serializer
	Identifier  string
	BasePath    string
	LevelDBPath string
	Logger      *zap.Logger
}

const retryCount = 5
const retryDelay = 1 * time.Second

func (S *LevelDbStore) StartUpdateCrl(info *crlreader.CRLMetaInfo) error {
	metaInfoBytes, err := S.Serializer.SerializeMetaInfo(info)
	if err != nil {
		return fmt.Errorf("could not serialize CRLMetaInfo: %v", err)
	}
	hash := hashing.Sum64(MetaInfoKey)
	err = S.Db.Put(hash, metaInfoBytes, nil)
	if err != nil {
		return fmt.Errorf("could not update CRLMetaInfo: %v", err)
	}
	return nil
}

func (S *LevelDbStore) InsertRevokedCert(entry *crlreader.CRLEntry) error {
	s := entry.Issuer.String() + "_" + entry.RevokedCertificate.SerialNumber.String()
	revokedCertBytes, err := S.Serializer.SerializeRevokedCert(entry.RevokedCertificate)
	if err != nil {
		return fmt.Errorf("could not serialize CRLEntry: %v", err)
	}
	hash := hashing.Sum64(s)
	err = S.Db.Put(hash, revokedCertBytes, nil)
	if err != nil {
		return fmt.Errorf("could not insert crl entry: %v", err)
	}
	return nil
}
func (S *LevelDbStore) GetCertRevocationStatus(issuer *pkix.RDNSequence, certSerial *big.Int) (*core.RevocationStatus, error) {
	s := issuer.String() + "_" + certSerial.String()
	hash := hashing.Sum64(s)
	revokedCertBytes, err := S.Db.Get(hash, nil)
	revoked := false
	var revokedCert *pkix.RevokedCertificate
	if err == nil {
		revokedCert, err = S.Serializer.DeserializeRevokedCert(revokedCertBytes)
		revoked = true
		if err != nil {
			return nil, fmt.Errorf("could not deserialize revoked cert: %v", err)
		}
	}
	return &core.RevocationStatus{
		Revoked:             revoked,
		CRLRevokedCertEntry: revokedCert,
	}, nil
}

func (S *LevelDbStore) GetCRLMetaInfo() (*crlreader.CRLMetaInfo, error) {
	hash := hashing.Sum64(MetaInfoKey)
	crlMetaBytes, err := S.Db.Get(hash, nil)
	if err == nil {
		return S.Serializer.DeserializeMetaInfo(crlMetaBytes)
	}
	return nil, err
}

func (S *LevelDbStore) GetCRLExtMetaInfo() (*crlreader.ExtendedCRLMetaInfo, error) {
	hash := hashing.Sum64(ExtendedMetaInfoKey)
	crlMetaBytes, err := S.Db.Get(hash, nil)
	if err == nil {
		return S.Serializer.DeserializeMetaInfoExt(crlMetaBytes)
	}
	return nil, err
}

func (S *LevelDbStore) UpdateExtendedMetaInfo(extMetaInfo *crlreader.ExtendedCRLMetaInfo) error {
	extMetaInfoBytes, err := S.Serializer.SerializeMetaInfoExt(extMetaInfo)
	if err != nil {
		return fmt.Errorf("could not serialize ExtendedCRLMetaInfo: %v", err)
	}
	hash := hashing.Sum64(ExtendedMetaInfoKey)
	err = S.Db.Put(hash, extMetaInfoBytes, nil)
	if err != nil {
		return fmt.Errorf("could not update ExtendedCRLMetaInfo: %v", err)
	}
	return nil
}

func (S *LevelDbStore) UpdateSignatureCertificate(entry *core.CertificateChainEntry) error {
	hash := hashing.Sum64(SignatureCertKey)
	err := S.Db.Put(hash, entry.RawCertificate, nil)
	if err != nil {
		return fmt.Errorf("could not update signature certificate: %v", err)
	}
	return nil
}

func (S *LevelDbStore) GetCRLSignatureCert() (*core.CertificateChainEntry, error) {
	hash := hashing.Sum64(SignatureCertKey)
	certBytes, err := S.Db.Get(hash, nil)
	if err != nil {
		return nil, fmt.Errorf("could not find signature key for crl: %v", err)
	}
	cert, err := S.Serializer.DeserializeSignatureCert(certBytes)
	if err != nil {
		return nil, fmt.Errorf("could not deserialize CRL signature certificate: %v", err)
	}
	return &core.CertificateChainEntry{RawCertificate: certBytes, Certificate: cert}, nil
}

func (S *LevelDbStore) UpdateCRLLocations(crlLocations *core.CRLLocations) error {
	crlLocationBytes, err := S.Serializer.SerializeCRLLocations(crlLocations)
	if err != nil {
		return fmt.Errorf("could not serialize CRLLocations: %v", err)
	}
	hash := hashing.Sum64(CRLLocationKey)
	err = S.Db.Put(hash, crlLocationBytes, nil)
	if err != nil {
		return fmt.Errorf("could not update CRLLocations: %v", err)
	}
	return nil
}

func (S *LevelDbStore) GetCRLLocations() (*core.CRLLocations, error) {
	hash := hashing.Sum64(CRLLocationKey)
	crlLocationBytes, err := S.Db.Get(hash, nil)
	if err == nil {
		return S.Serializer.DeserializeCRLLocations(crlLocationBytes)
	}
	return nil, err
}

func (S *LevelDbStore) IsEmpty() bool {
	hash := hashing.Sum64(MetaInfoKey)
	has, err := S.Db.Has(hash, nil)
	if err != nil {
		return true
	}
	if has == false {
		return true
	}
	return false
}

func (S *LevelDbStore) Update(store interface{}) error {
	var levelDbNew, ok = store.(*LevelDbStore)
	if ok == false {
		return errors.New("invalid update store type")
	}
	err := S.closeDbWithRetries(S.Db)
	if err != nil {
		return err
	}
	err = S.closeDbWithRetries(levelDbNew.Db)
	if err != nil {
		return err
	}
	levelDBPath := filepath.Join(S.BasePath, S.Identifier)
	levelDBPathTemp, err := S.renameWithRetriesToTempDir(S.LevelDBPath)
	if err != nil {
		return err
	}
	err = S.renameWithRetries(levelDbNew.LevelDBPath, levelDBPath)
	if err != nil {
		return err
	}

	err = S.removeWithRetries(levelDBPathTemp)
	if err != nil {
		S.Logger.Warn("failed to delete temporary path, will be deleted on next restart", zap.String("path", levelDBPathTemp))
	}
	db, err := openDbWithRetries(levelDBPath, S.Logger)
	if err != nil {
		return err
	}
	S.Db = db
	return nil
}

func (S *LevelDbStore) closeDbWithRetries(db *leveldb.DB) error {
	err := utils.Retry(retryCount, retryDelay, S.Logger, func() error {
		return db.Close()
	})
	return err
}

func (S *LevelDbStore) removeWithRetries(dirToRemove string) error {
	err := utils.Retry(retryCount, retryDelay, S.Logger, func() error {
		return os.RemoveAll(dirToRemove)
	})
	return err
}

func (S *LevelDbStore) renameWithRetries(oldPath string, newPath string) error {
	err := utils.Retry(retryCount, retryDelay, S.Logger, func() error {
		return os.Rename(oldPath, newPath)
	})
	return err
}

func (S *LevelDbStore) renameWithRetriesToTempDir(oldPath string) (newPath string, err error) {
	err = utils.Retry(retryCount, retryDelay, S.Logger, func() error {
		newPath, err = createRandomFileName(S.BasePath)
		if err != nil {
			return err
		}
		return os.Rename(oldPath, newPath)
	})
	if err != nil {
		return "", err
	}
	return newPath, nil
}

func createRandomFileName(basePath string) (string, error) {
	newUUID, err := uuid.NewUUID()
	if err != nil {
		return "", err
	}
	newPath := filepath.Join(basePath, "crl_"+newUUID.String()+"_tmp")
	return newPath, nil
}

func (S *LevelDbStore) Close() {
	err := S.closeDbWithRetries(S.Db)
	if err != nil {
		S.Logger.Warn("failed to close database", zap.Error(err))
	}
}

func (S *LevelDbStore) Delete() error {
	err := S.removeWithRetries(S.LevelDBPath)
	if err != nil {
		return err
	}
	return nil
}

type LevelDbStoreFactory struct {
	Serializer Serializer
	BasePath   string
	Logger     *zap.Logger
}

func (F LevelDbStoreFactory) CreateStore(identifier string, temporary bool) (CRLStore, error) {
	levelDBPath := filepath.Join(F.BasePath, identifier)
	if temporary {
		dir, err := createTempDirWithRetries(F.BasePath, F.Logger)
		if err != nil {
			return nil, err
		}
		levelDBPath = dir
	}

	err := os.MkdirAll(levelDBPath, 0700)
	if err != nil {
		return nil, fmt.Errorf("could not create dirctory for crl storage in %s cause: %v", levelDBPath, err)
	}
	db, err := openDbWithRetries(levelDBPath, F.Logger)
	if err != nil {
		return nil, fmt.Errorf("could not create leveldb store: %v", err)
	}
	return &LevelDbStore{
		Db:          db,
		Serializer:  F.Serializer,
		Identifier:  identifier,
		BasePath:    F.BasePath,
		LevelDBPath: levelDBPath,
		Logger:      F.Logger,
	}, nil
}

func createTempDirWithRetries(basePath string, logger *zap.Logger) (string, error) {
	var newPath = ""
	err := utils.Retry(retryCount, retryDelay, logger, func() (err error) {
		newPath, err = createRandomFileName(basePath)
		if err != nil {
			return err
		}
		err = os.Mkdir(newPath, 0700)
		if err != nil {
			return err
		}
		return nil
	})
	return newPath, err

}

func openDbWithRetries(levelDBPath string, logger *zap.Logger) (*leveldb.DB, error) {
	var db *leveldb.DB
	err := utils.Retry(retryCount, retryDelay, logger, func() (err error) {
		db, err = leveldb.OpenFile(levelDBPath, nil)
		return err
	})
	return db, err
}
