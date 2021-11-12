package crlreader

import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/asn1parser"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/hashing"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/pemreader"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/signatureverify"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader/extensionsupport"
	asn1crypto "golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
	"os"
	"time"
)

type CRLMetaInfo struct {
	Issuer     pkix.RDNSequence
	ThisUpdate time.Time
	NextUpdate time.Time `asn1:"tag:0,optional"`
}

type ExtendedCRLMetaInfo struct {
	CRLNumber *big.Int `asn1:"tag:0,optional"`
}

type CRLEntry struct {
	Issuer             *pkix.RDNSequence
	RevokedCertificate *pkix.RevokedCertificate
}

type CRLReadResult struct {
	HashAndVerifyStrategy *signatureverify.HashAndVerifyStrategies
	Signature             *asn1parser.BitString
	CalculatedSignature   []byte
	Issuer                *pkix.RDNSequence
	CRLExtensions         *[]pkix.Extension
}

type CRLProcessor interface {
	StartUpdateCrl(crlMetaInfo *CRLMetaInfo) error
	InsertRevokedCertificate(entry *CRLEntry) error
	UpdateExtendedMetaInfo(info *ExtendedCRLMetaInfo) error
	UpdateSignatureCertificate(entry *core.CertificateChainEntry) error
}

func ReadCRL(crlProcessor CRLProcessor, crlFilePath string) (*CRLReadResult, error) {

	crlFile, err := os.Open(crlFilePath)
	if err != nil {
		return nil, err
	}
	defer crlFile.Close()
	algorithmIdentifier, err := findAlgorithmIdentifierInCRL(crlFile)
	if err != nil {
		return nil, err
	}
	err = seekToCRLBegin(crlFile)
	reader := newHashingCRLReader(crlFile)

	certificateListTL, err := asn1parser.ReadTagLength(&reader)
	if err != nil {
		return nil, err
	}
	err = asn1parser.ExpectTag(asn1crypto.SEQUENCE, certificateListTL.Tag)
	if err != nil {
		return nil, err
	}

	strategies, err := signatureverify.LookupHashAndVerifyStrategies(*algorithmIdentifier)
	if err != nil {
		return nil, err
	}

	reader.StartHashCalculation(strategies.HashStrategy)
	tbsCertListTL, err := asn1parser.ReadTagLength(&reader)
	if err != nil {
		return nil, err
	}
	err = asn1parser.ExpectTag(asn1crypto.SEQUENCE, tbsCertListTL.Tag)
	if err != nil {
		return nil, err
	}
	version := 1
	if versionExists(reader) {
		version, err = parseVersion(reader, version)
		if err != nil {
			return nil, err
		}
	}
	if version > 2 {
		return nil, errors.New(fmt.Sprintf("CRL version %d is an unknown version", version))
	}
	_, _ = readAlgorithmIdentifier(&reader) //skip algorithm identifier
	issuer := new(pkix.RDNSequence)
	err = asn1parser.ReadStruct(&reader, issuer)
	if err != nil {
		return nil, err
	}
	thisUpdate, err := asn1parser.ReadUtcTime(&reader)
	if err != nil {
		return nil, err
	}
	var nextUpdate *time.Time
	if nextUpdateTimeExists(reader) {
		utcTime, err := asn1parser.ReadUtcTime(&reader)
		if err != nil {
			return nil, err
		}
		nextUpdate = utcTime
	}

	metaInfo := CRLMetaInfo{
		*issuer,
		*thisUpdate,
		*nextUpdate,
	}
	err = crlProcessor.StartUpdateCrl(&metaInfo)
	if err != nil {
		return nil, err
	}
	if revokedCertificateListExists(reader) {
		err := parseRevokedCertificateList(issuer, reader, crlProcessor)
		if err != nil {
			return nil, err
		}
	}
	var crlExtensions *[]pkix.Extension = nil
	var crlNumber *big.Int = nil
	if extensionsExists(reader, version) {
		crlExtensions, err = parseExtensions(reader)
		if err != nil {
			return nil, err
		}
		crlNumber, err = parseCRlNumberIfExists(crlExtensions)
		if err != nil {
			return nil, err
		}

	}
	extendedMetaInfo := ExtendedCRLMetaInfo{
		crlNumber,
	}
	err = crlProcessor.UpdateExtendedMetaInfo(&extendedMetaInfo)
	if err != nil {
		return nil, err
	}
	err = extensionsupport.CheckForCriticalUnhandledCRLExtensions(crlExtensions)
	if err != nil {
		return nil, err
	}
	calculatedSignature := reader.FinishHashCalculation()
	_, _ = readAlgorithmIdentifier(&reader) //skip algorithm identifier / we already parsed it
	signatureBitString, err := asn1parser.ParseBitString(&reader)
	if err != nil {
		return nil, err
	}

	return &CRLReadResult{
		HashAndVerifyStrategy: strategies,
		Signature:             signatureBitString,
		CalculatedSignature:   calculatedSignature,
		Issuer:                issuer,
		CRLExtensions:         crlExtensions,
	}, nil
}

func newHashingCRLReader(crlFile *os.File) hashing.HashingReaderWrapper {
	var reader hashing.HashingReaderWrapper
	_, pemFile := pemreader.IsPemFile(crlFile)
	if pemFile {
		reader = newHashingPEMCRLReader(crlFile)
	} else {
		reader = newHashingDERCRLReader(crlFile)
	}
	return reader
}

func parseCRlNumberIfExists(crlExtensions *[]pkix.Extension) (*big.Int, error) {
	extension := extensionsupport.FindExtension(extensionsupport.OidCrlExtCrlNumber, crlExtensions)
	if extension != nil {
		return asn1parser.ReadBigInt(bufio.NewReader(bytes.NewReader(extension.Value)))
	}
	return nil, nil
}

func seekToCRLBegin(crlFile *os.File) error {
	_, err := crlFile.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("could not seek to begin of crl file:  %v", err)
	}
	return err
}

func nextUpdateTimeExists(reader hashing.HashingReaderWrapper) bool {
	possibleTimeTL, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return possibleTimeTL.Tag == asn1.TagUTCTime
}

func parseVersion(reader hashing.HashingReaderWrapper, version int) (int, error) {
	//skip version tagLength
	_, _ = asn1parser.ReadTagLength(&reader)
	readUint8, err := asn1parser.ReadUint8(&reader)
	if err != nil {
		return 0, err
	}
	version = int(readUint8 + 1)
	return version, nil
}

func versionExists(reader hashing.HashingReaderWrapper) bool {
	tagLength, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return tagLength.Tag == asn1crypto.INTEGER && tagLength.Length.Length.Cmp(big.NewInt(int64(1))) == 0
}

func parseExtensions(reader hashing.HashingReaderWrapper) (*[]pkix.Extension, error) {
	_, _ = asn1parser.ReadTagLength(&reader) //skip context specific tag
	extensions := new([]pkix.Extension)
	err := asn1parser.ReadStruct(&reader, extensions)
	if err != nil {
		return nil, err
	}
	return extensions, nil
}

func extensionsExists(reader hashing.HashingReaderWrapper, version int) bool {
	contextSpecificTagLength, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return version > 1 && asn1parser.IsContextSpecificTagWithId(0, contextSpecificTagLength)
}

func parseRevokedCertificateList(issuer *pkix.RDNSequence, reader hashing.HashingReaderWrapper, processor CRLProcessor) error {
	revokedCertListTag, err := asn1parser.ReadTagLength(&reader)
	if err != nil {
		return err
	}
	err = asn1parser.ExpectTag(asn1crypto.SEQUENCE, revokedCertListTag.Tag)
	if err != nil {
		return err
	}
	for {
		revokedCertSeq, err := asn1parser.PeekTagLength(&reader, 0)
		if err != nil {
			return err
		}

		if revokedCertSeq.Tag != asn1crypto.SEQUENCE {
			break
		}
		revokedCert := new(pkix.RevokedCertificate)
		err = asn1parser.ReadStruct(&reader, revokedCert)
		if err != nil {
			return err
		}
		err = processor.InsertRevokedCertificate(&CRLEntry{
			issuer,
			revokedCert,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func revokedCertificateListExists(reader hashing.HashingReaderWrapper) bool {
	length, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return length.Tag == asn1crypto.SEQUENCE
}

func findAlgorithmIdentifierInCRL(file *os.File) (*pkix.AlgorithmIdentifier, error) {
	var reader = newHashingCRLReader(file)
	algoIdOffset := big.NewInt(0)
	certificateListTL, err := asn1parser.ReadTagLength(reader)
	if err != nil {
		return nil, err
	}
	err = asn1parser.ExpectTag(asn1crypto.SEQUENCE, certificateListTL.Tag)
	if err != nil {
		return nil, err
	}
	tbsCertListTL, err := asn1parser.PeekTagLength(reader, 0)
	if err != nil {
		return nil, err
	}
	algoIdOffset = algoIdOffset.Add(algoIdOffset, tbsCertListTL.CalculateTLVLength())
	err = reader.Discard(algoIdOffset.Int64())
	if err != nil {
		return nil, err
	}
	value := new(pkix.AlgorithmIdentifier)
	err = asn1parser.ReadStruct(reader, value)
	if err != nil {
		return nil, err
	}
	return value, nil

}

func readAlgorithmIdentifier(reader asn1parser.Asn1Reader) (*pkix.AlgorithmIdentifier, error) {
	value := new(pkix.AlgorithmIdentifier)
	err := asn1parser.ReadStruct(reader, value)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func newHashingDERCRLReader(crlFile *os.File) hashing.HashingReaderWrapper {
	var reader = hashing.HashingReaderWrapper{
		Reader:    bufio.NewReader(crlFile),
		Signature: "",
	}
	return reader
}

func newHashingPEMCRLReader(crlFile *os.File) hashing.HashingReaderWrapper {
	pemReader := pemreader.NewPemReader(bufio.NewReader(crlFile))
	decoder := base64.NewDecoder(base64.RawStdEncoding, &pemReader)

	var reader = hashing.HashingReaderWrapper{
		Reader:    bufio.NewReader(decoder),
		Signature: "",
	}
	return reader

}
