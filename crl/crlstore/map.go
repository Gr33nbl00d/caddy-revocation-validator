package crlstore

import (
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/hashing"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"go.uber.org/zap"
	"math/big"
)

type MapStore struct {
	Map        map[string][]byte
	Serializer Serializer
	Logger     *zap.Logger
}

func (S *MapStore) StartUpdateCrl(info *crlreader.CRLMetaInfo) error {
	metaInfoBytes, err := S.Serializer.SerializeMetaInfo(info)
	if err != nil {
		return fmt.Errorf("could not serialize CRLMetaInfo: %v", err)
	}
	err = S.set(MetaInfoKey, metaInfoBytes)
	if err != nil {
		return fmt.Errorf("could not update CRLMetaInfo: %v", err)
	}
	return nil
}

func (S *MapStore) InsertRevokedCert(entry *crlreader.CRLEntry) error {
	s := entry.Issuer.String() + "_" + entry.RevokedCertificate.SerialNumber.String()
	revokedCertBytes, err := S.Serializer.SerializeRevokedCert(entry.RevokedCertificate)
	if err != nil {
		return fmt.Errorf("could not serialize CRLEntry: %v", err)
	}
	err = S.set(s, revokedCertBytes)
	if err != nil {
		return fmt.Errorf("could not insert crl entry: %v", err)
	}
	return nil

}
func (S *MapStore) GetCertRevocationStatus(issuer *pkix.RDNSequence, certSerial *big.Int) (*core.RevocationStatus, error) {
	s := issuer.String() + "_" + certSerial.String()
	revokedCertBytes, err := S.get(s)

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

func (S *MapStore) GetCRLMetaInfo() (*crlreader.CRLMetaInfo, error) {
	crlMetaBytes, err := S.get(MetaInfoKey)
	if err == nil {
		return S.Serializer.DeserializeMetaInfo(crlMetaBytes)
	}
	return nil, err
}

func (S *MapStore) GetCRLExtMetaInfo() (*crlreader.ExtendedCRLMetaInfo, error) {
	crlMetaBytes, err := S.get(ExtendedMetaInfoKey)
	if err == nil {
		return S.Serializer.DeserializeMetaInfoExt(crlMetaBytes)
	}
	return nil, err
}

func (S *MapStore) UpdateExtendedMetaInfo(extMetaInfo *crlreader.ExtendedCRLMetaInfo) error {
	extMetaInfoBytes, err := S.Serializer.SerializeMetaInfoExt(extMetaInfo)
	if err != nil {
		return fmt.Errorf("could not serialize ExtendedCRLMetaInfo: %v", err)
	}
	err = S.set(ExtendedMetaInfoKey, extMetaInfoBytes)
	if err != nil {
		return fmt.Errorf("could not update ExtendedCRLMetaInfo: %v", err)
	}
	return nil
}

func (S *MapStore) UpdateSignatureCertificate(entry *core.CertificateChainEntry) error {
	err := S.set(SignatureCertKey, entry.RawCertificate)
	if err != nil {
		return fmt.Errorf("could not update signature certificate: %v", err)
	}
	return nil
}

func (S *MapStore) GetCRLSignatureCert() (*core.CertificateChainEntry, error) {
	certBytes, err := S.get(SignatureCertKey)
	if err != nil {
		return nil, fmt.Errorf("could not find signature key for crl: %v", err)
	}
	cert, err := S.Serializer.DeserializeSignatureCert(certBytes)
	if err != nil {
		return nil, fmt.Errorf("could not deserialize CRL signature certificate: %v", err)
	}
	return &core.CertificateChainEntry{RawCertificate: certBytes, Certificate: cert}, nil
}

func (S *MapStore) UpdateCRLLocations(crlLocations *core.CRLLocations) error {
	crlLocationBytes, err := S.Serializer.SerializeCRLLocations(crlLocations)
	if err != nil {
		return fmt.Errorf("could not serialize CRLLocations: %v", err)
	}
	err = S.set(CRLLocationKey, crlLocationBytes)
	if err != nil {
		return fmt.Errorf("could not update CRLLocations: %v", err)
	}
	return nil
}

func (S *MapStore) GetCRLLocations() (*core.CRLLocations, error) {
	crlLocationBytes, err := S.get(CRLLocationKey)
	if err == nil {
		return S.Serializer.DeserializeCRLLocations(crlLocationBytes)
	}
	return nil, err
}

func (S *MapStore) IsEmpty() bool {
	return len(S.Map) == 0
}

func (S *MapStore) Update(store interface{}) error {
	var storeNew, ok = store.(*MapStore)
	if ok == false {
		return errors.New("invalid update store type")
	}
	S.Map = storeNew.Map
	storeNew.close()
	return nil
}

func (S *MapStore) Close() {
}

func (S *MapStore) Delete() error {

	return nil
}

func (S *MapStore) set(key string, bytes []byte) error {
	S.Map[string(hashing.Sum64(key))] = bytes
	return nil
}

func (S *MapStore) get(key string) ([]byte, error) {
	bytes := S.Map[string(hashing.Sum64(key))]
	if bytes == nil {
		return nil, errors.New("entry not found")
	}
	return bytes, nil
}

func (S *MapStore) close() {
	S.Map = nil
}

type MapStoreFactory struct {
	Serializer Serializer
	Logger     *zap.Logger
}

func (F MapStoreFactory) CreateStore(_ string, _ bool) (CRLStore, error) {
	return &MapStore{
		Map:        make(map[string][]byte, 0),
		Serializer: F.Serializer,
		Logger:     F.Logger,
	}, nil
}
