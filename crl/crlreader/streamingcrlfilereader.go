package crlreader

import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/asn1parser"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/hashing"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/signatureverify"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader/extensionsupport"
	asn1crypto "golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
	"os"
	"time"
)

type StreamingCRLFileReader struct {
	hashingCRLReaderFactory HashingCRLReaderFactory
}

func (S StreamingCRLFileReader) ReadCRL(crlProcessor CRLProcessor, crlFilePath string) (*CRLReadResult, error) {

	crlFile, err := os.Open(crlFilePath)
	if err != nil {
		return nil, err
	}
	defer utils.CloseWithErrorHandling(crlFile.Close)
	algorithmIdentifier, err := S.findAlgorithmIdentifierInCRL(crlFile)
	if err != nil {
		return nil, err
	}
	err = S.seekToCRLBegin(crlFile)
	reader := S.hashingCRLReaderFactory.newHashingCRLReader(crlFile)

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
	if S.versionExists(reader) {
		version, err = S.parseVersion(reader, version)
		if err != nil {
			return nil, err
		}
	}
	if version > 2 {
		return nil, errors.New(fmt.Sprintf("CRL version %d is an unknown version", version))
	}
	_, _ = S.readAlgorithmIdentifier(&reader) //skip algorithm identifier
	issuer := new(pkix.RDNSequence)
	err = asn1parser.ReadStruct(&reader, issuer)
	if err != nil {
		return nil, err
	}
	thisUpdate, err := asn1parser.ReadUtcTime(&reader)
	if err != nil {
		return nil, err
	}
	var nextUpdate time.Time
	if S.nextUpdateTimeExists(reader) {
		utcTime, err := asn1parser.ReadUtcTime(&reader)
		if err != nil {
			return nil, err
		}
		nextUpdate = *utcTime
	}

	metaInfo := CRLMetaInfo{
		*issuer,
		*thisUpdate,
		nextUpdate,
	}
	err = crlProcessor.StartUpdateCrl(&metaInfo)
	if err != nil {
		return nil, err
	}
	if S.revokedCertificateListExists(reader) {
		err := S.parseRevokedCertificateList(issuer, reader, crlProcessor)
		if err != nil {
			return nil, err
		}
	}
	var crlExtensions *[]pkix.Extension = nil
	var crlNumber *big.Int = nil
	if S.extensionsExists(reader, version) {
		crlExtensions, err = S.parseExtensions(reader)
		if err != nil {
			return nil, err
		}
		crlNumber, err = S.parseCRlNumberIfExists(crlExtensions)
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
	_, _ = S.readAlgorithmIdentifier(&reader) //skip algorithm identifier / we already parsed it
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

func (S StreamingCRLFileReader) revokedCertificateListExists(reader hashing.HashingReaderWrapper) bool {
	length, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return length.Tag == asn1crypto.SEQUENCE
}

func (S StreamingCRLFileReader) findAlgorithmIdentifierInCRL(file *os.File) (*pkix.AlgorithmIdentifier, error) {
	var reader = S.hashingCRLReaderFactory.newHashingCRLReader(file)
	algoIdOffset := big.NewInt(0)
	certificateListTL, err := asn1parser.ReadTagLength(&reader)
	if err != nil {
		return nil, err
	}
	err = asn1parser.ExpectTag(asn1crypto.SEQUENCE, certificateListTL.Tag)
	if err != nil {
		return nil, err
	}
	tbsCertListTL, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return nil, err
	}
	algoIdOffset = algoIdOffset.Add(algoIdOffset, tbsCertListTL.CalculateTLVLength())
	err = reader.Discard(algoIdOffset.Int64())
	if err != nil {
		return nil, err
	}
	value := new(pkix.AlgorithmIdentifier)
	err = asn1parser.ReadStruct(&reader, value)
	if err != nil {
		return nil, err
	}
	return value, nil

}

func (S StreamingCRLFileReader) readAlgorithmIdentifier(reader asn1parser.Asn1Reader) (*pkix.AlgorithmIdentifier, error) {
	value := new(pkix.AlgorithmIdentifier)
	err := asn1parser.ReadStruct(reader, value)
	if err != nil {
		return nil, err
	}
	return value, nil
}

func (S StreamingCRLFileReader) parseCRlNumberIfExists(crlExtensions *[]pkix.Extension) (*big.Int, error) {
	extension := extensionsupport.FindExtension(extensionsupport.OidCrlExtCrlNumber, crlExtensions)
	if extension != nil {
		return asn1parser.ReadBigInt(bufio.NewReader(bytes.NewReader(extension.Value)))
	}
	return nil, nil
}

func (S StreamingCRLFileReader) seekToCRLBegin(crlFile *os.File) error {
	_, err := crlFile.Seek(0, 0)
	if err != nil {
		return fmt.Errorf("could not seek to begin of crl file:  %v", err)
	}
	return err
}

func (S StreamingCRLFileReader) nextUpdateTimeExists(reader hashing.HashingReaderWrapper) bool {
	possibleTimeTL, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return possibleTimeTL.Tag == asn1.TagUTCTime
}

func (S StreamingCRLFileReader) parseVersion(reader hashing.HashingReaderWrapper, version int) (int, error) {
	//skip version tagLength
	_, _ = asn1parser.ReadTagLength(&reader)
	readUint8, err := asn1parser.ReadUint8(&reader)
	if err != nil {
		return 0, err
	}
	version = int(readUint8 + 1)
	return version, nil
}

func (S StreamingCRLFileReader) versionExists(reader hashing.HashingReaderWrapper) bool {
	tagLength, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return tagLength.Tag == asn1crypto.INTEGER && tagLength.Length.Length.Cmp(big.NewInt(int64(1))) == 0
}

func (S StreamingCRLFileReader) parseExtensions(reader hashing.HashingReaderWrapper) (*[]pkix.Extension, error) {
	_, _ = asn1parser.ReadTagLength(&reader) //skip context specific tag
	extensions := new([]pkix.Extension)
	err := asn1parser.ReadStruct(&reader, extensions)
	if err != nil {
		return nil, err
	}
	return extensions, nil
}

func (S StreamingCRLFileReader) extensionsExists(reader hashing.HashingReaderWrapper, version int) bool {
	contextSpecificTagLength, err := asn1parser.PeekTagLength(&reader, 0)
	if err != nil {
		return false
	}
	return version > 1 && asn1parser.IsContextSpecificTagWithId(0, contextSpecificTagLength)
}

func (S StreamingCRLFileReader) parseRevokedCertificateList(issuer *pkix.RDNSequence, reader hashing.HashingReaderWrapper, processor CRLProcessor) error {
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
