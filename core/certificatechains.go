package core

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/asn1parser"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader/extensionsupport"
)

type CertificateChains struct {
	CertificateChainList []CertificateChain
}

func (c *CertificateChains) AddCertificateChain(chain CertificateChain) {
	c.CertificateChainList = append(c.CertificateChainList, chain)
}

type CertificateChain struct {
	CertificateChainEntryList []CertificateChainEntry
}

func (c *CertificateChain) AddCertificateChainEntry(entry *CertificateChainEntry) {
	c.CertificateChainEntryList = append(c.CertificateChainEntryList, *entry)
}

type CertificateChainEntry struct {
	RawCertificate []byte
	Certificate    *x509.Certificate
}

func NewCertificateChains(verifiedChains [][]*x509.Certificate, trustedSignerCerts []*x509.Certificate) *CertificateChains {
	chains := &CertificateChains{
		CertificateChainList: make([]CertificateChain, 0),
	}
	for _, verifiedChain := range verifiedChains {
		chain := &CertificateChain{
			CertificateChainEntryList: make([]CertificateChainEntry, 0),
		}
		for _, verifiedChainEntry := range verifiedChain {
			entry := CertificateChainEntry{
				RawCertificate: verifiedChainEntry.Raw,
				Certificate:    verifiedChainEntry,
			}
			chain.AddCertificateChainEntry(&entry)
		}
		chains.AddCertificateChain(*chain)
	}
	for _, trustedSignerCert := range trustedSignerCerts {
		chain := &CertificateChain{
			CertificateChainEntryList: make([]CertificateChainEntry, 0),
		}
		entry := CertificateChainEntry{
			RawCertificate: trustedSignerCert.Raw,
			Certificate:    trustedSignerCert,
		}
		chain.AddCertificateChainEntry(&entry)
		chains.AddCertificateChain(*chain)
	}

	return chains
}

func NewCertificateChainsFromEntry(chainEntry *CertificateChainEntry) *CertificateChains {
	chains := &CertificateChains{
		CertificateChainList: make([]CertificateChain, 0),
	}
	chain := &CertificateChain{
		CertificateChainEntryList: make([]CertificateChainEntry, 0),
	}
	chain.AddCertificateChainEntry(chainEntry)
	chains.AddCertificateChain(*chain)
	return chains
}

//Implemenation according to rfc5280 section 5.2.1
func FindCertificateIssuerCandidates(issuer *pkix.RDNSequence, extensions *[]pkix.Extension, algorithmID x509.PublicKeyAlgorithm, chains *CertificateChains) ([]*CertificateChainEntry, error) {
	keyIdentifierExtension := extensionsupport.FindExtension(extensionsupport.OidCertExtAuthorityKeyId, extensions)
	if keyIdentifierExtension == nil {
		return findCertificateCandidatesByIssuerAndAlgorithm(issuer, algorithmID, chains)
	} else {
		authorityKeyIdentifier, err := parseKeyIdentifierFromExtension(keyIdentifierExtension)
		if err != nil {
			return nil, err
		}
		if authorityKeyIdentifier.AuthorityCertSerialNumber != nil && &authorityKeyIdentifier.AuthorityCertIssuer.Raw != nil {
			return findCertificateBySerialAndIssuer(authorityKeyIdentifier, chains)
		} else if authorityKeyIdentifier.KeyIdentifier != nil {
			return findCertificateCandidatesFromKeyIdentifier(chains, authorityKeyIdentifier)
		} else {
			return nil, errors.New("unsupported Authority Key Identifier combination")
		}
	}
}

func findCertificateCandidatesFromKeyIdentifier(verifiedChains *CertificateChains, authorityKeyIdentifier *extensionsupport.AuthorityKeyIdentifier) ([]*CertificateChainEntry, error) {
	var certificateCandidates = make([]*CertificateChainEntry, 0)
	for _, verifiedChain := range verifiedChains.CertificateChainList {
		for _, certCandidate := range verifiedChain.CertificateChainEntryList {
			subjectKeyIdentifierExtension := extensionsupport.FindExtension(extensionsupport.OidCertExtSubjectKeyId, &certCandidate.Certificate.Extensions)
			if subjectKeyIdentifierExtension != nil {
				subjectKeyIdReader := bufio.NewReader(bytes.NewReader(subjectKeyIdentifierExtension.Value))
				subjectKeyId, err := asn1parser.ParseOctetString(subjectKeyIdReader)
				if err != nil {
					return nil, err
				}
				if bytes.Compare(authorityKeyIdentifier.KeyIdentifier, subjectKeyId) == 0 {
					certificateCandidates = append(certificateCandidates, &certCandidate)
				}
			}
		}
	}
	return certificateCandidates, nil
}

func findCertificateBySerialAndIssuer(identifier *extensionsupport.AuthorityKeyIdentifier, verifiedChains *CertificateChains) ([]*CertificateChainEntry, error) {
	var certificateCandidates = make([]*CertificateChainEntry, 0)
	for _, verifiedChain := range verifiedChains.CertificateChainList {
		for _, certCandidate := range verifiedChain.CertificateChainEntryList {
			if certCandidate.Certificate.SerialNumber.Cmp(identifier.AuthorityCertSerialNumber) == 0 {
				authorityCertIssuerDN := new(pkix.RDNSequence)
				if len(identifier.AuthorityCertIssuer.DirectoryName.Bytes) > 0 {
					reader := bufio.NewReader(bytes.NewReader(identifier.AuthorityCertIssuer.DirectoryName.Bytes))
					err := asn1parser.ReadStruct(reader, authorityCertIssuerDN)
					if err != nil {
						return nil, err
					}

					certCandidateIssuer, err := asn1parser.ParseIssuerRDNSequence(certCandidate.Certificate)
					if err != nil {
						return nil, err
					}

					if certCandidateIssuer.String() == authorityCertIssuerDN.String() {
						certificateCandidates = append(certificateCandidates, &certCandidate)
					}
				}
			}
		}
	}
	return certificateCandidates, nil
}

func findCertificateCandidatesByIssuerAndAlgorithm(issuer *pkix.RDNSequence, algorithmID x509.PublicKeyAlgorithm, verifiedChains *CertificateChains) ([]*CertificateChainEntry, error) {
	var certificateCandidates = make([]*CertificateChainEntry, 0)
	for _, verifiedChain := range verifiedChains.CertificateChainList {
		for _, certCandidate := range verifiedChain.CertificateChainEntryList {
			subjectRDNSequence, err := asn1parser.ParseSubjectRDNSequence(certCandidate.Certificate)
			if err != nil {
				return nil, err
			}
			if subjectRDNSequence.String() == issuer.String() {
				if certCandidate.Certificate.PublicKeyAlgorithm == algorithmID {
					certificateCandidates = append(certificateCandidates, &certCandidate)
				}
			}
		}
	}
	return certificateCandidates, nil
}

func parseKeyIdentifierFromExtension(keyIdentifierExtension *pkix.Extension) (*extensionsupport.AuthorityKeyIdentifier, error) {
	authorityKeyIdentifier := new(extensionsupport.AuthorityKeyIdentifier)
	_, err := asn1.Unmarshal(keyIdentifierExtension.Value, authorityKeyIdentifier)
	if err != nil {
		return nil, fmt.Errorf("could not parse AuthorityKeyIdentifier from extension")
	}
	return authorityKeyIdentifier, nil
}
