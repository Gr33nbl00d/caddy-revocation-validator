package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader/extensionsupport"
	"math/big"
	"testing"
	"time"
)

func TestFindCertificateIssuerCandidatesByIssuerAndAlgorithm(t *testing.T) {
	// Create a sample issuer RDNSequence
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	// Create a sample list of extensions (empty for this test)
	extensions := []pkix.Extension{}

	// Define the expected public key algorithm
	algorithmID := x509.RSA

	// Create a sample chain entry
	// Create a sample chain entry with a correctly encoded RawSubject
	subjectBytes, err := asn1.Marshal(*issuer)
	if err != nil {
		t.Fatalf("Error encoding subject: %v", err)
	}
	chainEntry := &CertificateChainEntry{
		RawCertificate: []byte("sample_certificate"),
		Certificate: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			RawSubject:         subjectBytes,
			PublicKeyAlgorithm: x509.RSA,
		},
	}

	// Create a CertificateChain instance and add the chain entry to it
	chain := &CertificateChain{}
	chain.AddCertificateChainEntry(chainEntry)

	// Create a CertificateChains instance and add the chain to it
	chains := &CertificateChains{}
	chains.AddCertificateChain(*chain)

	// Test the function
	candidates, err := FindCertificateIssuerCandidates(issuer, &extensions, algorithmID, chains)
	if err != nil {
		t.Fatalf("Error in FindCertificateIssuerCandidates: %v", err)
	}

	// Verify the test results with assertions

	// Check if the number of candidates is as expected
	if len(candidates) != 1 {
		t.Errorf("Expected 1 candidate, but got %d", len(candidates))
	}

	// Check if the candidate's CommonName matches the expected value
	expectedCommonName := "example.com"
	if candidates[0].Certificate.Subject.CommonName != expectedCommonName {
		t.Errorf("Expected CommonName to be '%s', but got '%s'", expectedCommonName, candidates[0].Certificate.Subject.CommonName)
	}
}

func TestFindCertificateIssuerCandidatesByIssuerAndAlgorithmWithOneNotMatching(t *testing.T) {
	// Create a sample issuer RDNSequence
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}

	// Create a sample list of extensions (empty for this test)
	extensions := []pkix.Extension{}

	// Define the expected public key algorithm
	algorithmID := x509.RSA

	// Create a sample chain entry that matches the issuer
	subjectBytes, err := asn1.Marshal(*issuer)
	if err != nil {
		t.Fatalf("Error encoding subject: %v", err)
	}
	chainEntry := &CertificateChainEntry{
		RawCertificate: []byte("sample_certificate_matching"),
		Certificate: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			RawSubject:         subjectBytes,
			PublicKeyAlgorithm: x509.RSA,
		},
	}

	// Create a sample chain entry that does not match the issuer
	otherIssuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Different Issuer",
			},
		},
	}
	otherSubjectBytes, err := asn1.Marshal(*otherIssuer)
	if err != nil {
		t.Fatalf("Error encoding other subject: %v", err)
	}
	chainEntryNonMatching := &CertificateChainEntry{
		RawCertificate: []byte("sample_certificate_non_matching"),
		Certificate: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			RawSubject:         otherSubjectBytes,
			PublicKeyAlgorithm: x509.RSA,
		},
	}

	// Create a CertificateChain instance and add the chain entries to it
	chain := &CertificateChain{}
	chain.AddCertificateChainEntry(chainEntry)
	chain.AddCertificateChainEntry(chainEntryNonMatching)

	// Create a CertificateChains instance and add the chain to it
	chains := &CertificateChains{}
	chains.AddCertificateChain(*chain)

	// Test the function for matching issuer
	candidates, err := FindCertificateIssuerCandidates(issuer, &extensions, algorithmID, chains)
	if err != nil {
		t.Fatalf("Error in FindCertificateIssuerCandidates: %v", err)
	}

	// Verify the test results for matching issuer

	// Check if the number of candidates is as expected
	if len(candidates) != 1 {
		t.Errorf("Expected 1 candidate for matching issuer, but got %d", len(candidates))
	}

	// Check if the candidate's CommonName matches the expected value
	expectedCommonName := "example.com"
	if candidates[0].Certificate.Subject.CommonName != expectedCommonName {
		t.Errorf("Expected CommonName to be '%s', but got '%s'", expectedCommonName, candidates[0].Certificate.Subject.CommonName)
	}
}

func TestFindCertificateIssuerWithWrongRDNSequenceBytes(t *testing.T) {
	// Create a sample issuer RDNSequence
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}

	// Create a sample list of extensions (empty for this test)
	extensions := []pkix.Extension{}

	// Define the expected public key algorithm
	algorithmID := x509.RSA

	//Create wrong rdnsequence bytes
	wrongBytes := []byte{0xcf, 0x01, 0x15, 0x13, 0x33}

	chainEntry := &CertificateChainEntry{
		RawCertificate: []byte("sample_certificate_matching"),
		Certificate: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			RawSubject:         wrongBytes,
			PublicKeyAlgorithm: x509.RSA,
		},
	}

	// Create a CertificateChain instance and add the chain entry to it
	chain := &CertificateChain{}
	chain.AddCertificateChainEntry(chainEntry)

	// Create a CertificateChains instance and add the chain to it
	chains := &CertificateChains{}
	chains.AddCertificateChain(*chain)

	_, err := FindCertificateIssuerCandidates(issuer, &extensions, algorithmID, chains)

	// Check if the error is not nil
	if err == nil {
		t.Errorf("Expected error, but got nil")
	}

	// Check if the error message contains "could not parse"
	expectedErrorMessage := "could not parse the RDNSequence: unexpected tag. Expected: 48 but found 207"
	if err.Error() != expectedErrorMessage {
		t.Errorf("Expected error message '%s', but got '%s'", expectedErrorMessage, err.Error())
	}

}

var oidMap = map[string]asn1.ObjectIdentifier{
	extensionsupport.OidCertExtAuthorityKeyId: asn1.ObjectIdentifier{2, 5, 29, 35},
}

func TestFindCertificateIssuerCandidatesWithKeyIdentifier(t *testing.T) {
	// Create a sample issuer RDNSequence
	issuer := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}
	// Create a sample list of extensions (empty for this test)
	extensions := []pkix.Extension{}

	// Define the expected public key algorithm
	algorithmID := x509.RSA

	// Create a sample chain entry
	// Create a sample chain entry with a correctly encoded RawSubject
	subjectBytes, err := asn1.Marshal(*issuer)
	if err != nil {
		t.Fatalf("Error encoding subject: %v", err)
	}

	// Create an additional extension with OID "2.5.29.14"
	subjectKeyIdentifierValue := asn1.RawValue{
		Tag:        4, // OCTET STRING
		Class:      asn1.ClassUniversal,
		IsCompound: false,
		Bytes:      []byte{0x01, 0x02, 0x03},
	}
	subjectKeyIdentifierBytes, err := asn1.Marshal(subjectKeyIdentifierValue)
	if err != nil {
		t.Fatalf("Error encoding SubjectKeyIdentifier extension value: %v", err)
	}
	subjectKeyIdentifierExtension := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 14}, // OID for SubjectKeyIdentifier
		Critical: true,
		Value:    subjectKeyIdentifierBytes,
	}
	certExtensions := []pkix.Extension{subjectKeyIdentifierExtension}

	chainEntry := &CertificateChainEntry{
		RawCertificate: []byte("sample_certificate"),
		Certificate: &x509.Certificate{
			Subject: pkix.Name{
				CommonName: "example.com",
			},
			SerialNumber:       big.NewInt(12345),
			RawSubject:         subjectBytes,
			RawIssuer:          subjectBytes,
			PublicKeyAlgorithm: x509.RSA,
			Extensions:         certExtensions,
		},
	}

	// Create a CertificateChain instance and add the chain entry to it
	chain := &CertificateChain{}
	chain.AddCertificateChainEntry(chainEntry)

	// Create a CertificateChains instance and add the chain to it
	chains := &CertificateChains{}
	chains.AddCertificateChain(*chain)

	testFindCertificateIssuerCandidatesWithNoAuthoritzKezIdentifier(t, issuer, extensions, algorithmID, chains)

	testFindCertificateIssuerCandidatesWithInvalidAuthorityKeyIdentifier(t, extensions, issuer, chains)

	testFindCertificateIssuerCandidatesWithSubjectKeyIdentifierMatchingAuthorityKeyIdentifier(t, extensions, issuer, chains)
}

func testFindCertificateIssuerCandidatesWithNoAuthoritzKezIdentifier(t *testing.T, issuer *pkix.RDNSequence, extensions []pkix.Extension, algorithmID x509.PublicKeyAlgorithm, chains *CertificateChains) {
	// Test case 1: No keyIdentifierExtension
	result1, err1 := FindCertificateIssuerCandidates(issuer, &extensions, algorithmID, chains)
	if err1 != nil {
		t.Errorf("Unexpected error in test case 1: %v", err1)
	}
	if len(result1) == 0 {
		t.Errorf("Expected non-empty result in test case 1, got empty result")
	}
}

func testFindCertificateIssuerCandidatesWithInvalidAuthorityKeyIdentifier(t *testing.T, extensions []pkix.Extension, issuer *pkix.RDNSequence, chains *CertificateChains) {
	// Test case 2: authoritzkeyIdentifierExtension with wrong data
	unsupportedKeyIdentifierExtension := pkix.Extension{
		Id:       oidMap[extensionsupport.OidCertExtAuthorityKeyId], // Use the mapping
		Critical: true,
		Value:    []byte{0x01, 0x02, 0x03}, // Unsupported data
	}
	extensions = []pkix.Extension{unsupportedKeyIdentifierExtension}
	result2, err2 := FindCertificateIssuerCandidates(issuer, &extensions, x509.RSA, chains)
	if err2 == nil {
		t.Errorf("Expected error in test case 2, got no error")
	}
	if len(result2) > 0 {
		t.Errorf("Expected empty result in test case 2, got non-empty result")
	}
	if err2 == nil || err2.Error() != "could not parse AuthorityKeyIdentifier from extension" {
		t.Errorf("Expected 'could not parse AuthorityKeyIdentifier from extension' error in test case 2, got: %v", err2)
	}
}

func testFindCertificateIssuerCandidatesWithSubjectKeyIdentifierMatchingAuthorityKeyIdentifier(t *testing.T, extensions []pkix.Extension, issuer *pkix.RDNSequence, chains *CertificateChains) {
	// Test case 3: keyIdentifierExtension with a valid matching keyIdentifier
	// Create a DirectoryName using marshalling
	directoryName := &pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{
				Type:  asn1.ObjectIdentifier{2, 5, 4, 3}, // OID for CommonName
				Value: "Test Issuer",
			},
		},
	}

	// Marshal the DirectoryName
	directoryNameBytes, err := asn1.Marshal(*directoryName)
	if err != nil {
		t.Errorf("Failed to marshal DirectoryName: %v", err)
	}
	validKeyIdentifierValue := []byte{0x01, 0x02, 0x03} // A valid keyIdentifier matching condition
	validAuthorityCertIssuer := extensionsupport.GeneralName{
		Rfc822Name: asn1.RawValue{
			Tag:   1, // Tag for IA5String
			Class: asn1.ClassContextSpecific,
			Bytes: []byte("test@example.com"),
		},
		DirectoryName: asn1.RawValue{
			Tag:   4, // Tag for DirectoryName
			Class: asn1.ClassContextSpecific,
			Bytes: directoryNameBytes, // Use the marshalled DirectoryName
		},
	}
	validAuthorityCertSerialNumber := big.NewInt(12345) // Example value, customize as needed
	authorityKeyIdentifier := extensionsupport.AuthorityKeyIdentifier{
		KeyIdentifier:             validKeyIdentifierValue,
		AuthorityCertIssuer:       validAuthorityCertIssuer,
		AuthorityCertSerialNumber: validAuthorityCertSerialNumber,
	}
	authorityKeyIdentifierBytes, err := asn1.Marshal(authorityKeyIdentifier)

	if err != nil {
		t.Errorf("Unexpected error in test case 3: %v", err)
	}

	validAuthorityKeyExtension := pkix.Extension{
		Id:       oidMap[extensionsupport.OidCertExtAuthorityKeyId], // Use the mapping
		Critical: true,
		Value:    authorityKeyIdentifierBytes,
	}
	extensions = []pkix.Extension{validAuthorityKeyExtension}
	result3, err3 := FindCertificateIssuerCandidates(issuer, &extensions, x509.RSA, chains)
	if err3 != nil {
		t.Errorf("Unexpected error in test case 3: %v", err3)
	}
	if len(result3) == 0 {
		t.Errorf("Expected non-empty result in test case 3, got empty result")
	}

	// Test case 4: keyIdentifierExtension without serialnumber
	authorityKeyIdentifierWithoutSerial := extensionsupport.AuthorityKeyIdentifier{
		KeyIdentifier:       validKeyIdentifierValue,
		AuthorityCertIssuer: validAuthorityCertIssuer,
	}
	authorityKeyIdentifierWithoutSerialBytes, err := asn1.Marshal(authorityKeyIdentifierWithoutSerial)

	if err != nil {
		t.Errorf("Unexpected error in test case 3: %v", err)
	}

	authorityKeyIdentifierWithoutSerialExtension := pkix.Extension{
		Id:       oidMap[extensionsupport.OidCertExtAuthorityKeyId], // Use the mapping
		Critical: true,
		Value:    authorityKeyIdentifierWithoutSerialBytes,
	}
	extensions = []pkix.Extension{authorityKeyIdentifierWithoutSerialExtension}
	result4, err4 := FindCertificateIssuerCandidates(issuer, &extensions, x509.RSA, chains)
	if err4 != nil {
		t.Errorf("Unexpected error in test case 4: %v", err3)
	}
	if len(result4) == 0 {
		t.Errorf("Expected non-empty result in test case 4, got empty result")
	}
}

func TestNewCertificateChains(t *testing.T) {
	// Generate self-signed certificates for testing
	cert1, _, err := generateSelfSignedCertificate("example1.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate 1: %v", err)
	}
	cert2, _, err := generateSelfSignedCertificate("example2.com")
	if err != nil {
		t.Fatalf("Failed to generate certificate 2: %v", err)
	}
	trustedSignerCert, _, err := generateSelfSignedCertificate("trusted-signer.com")
	if err != nil {
		t.Fatalf("Failed to generate trusted signer certificate: %v", err)
	}

	// Create some sample input data using the generated certificates
	verifiedChain1 := []*x509.Certificate{cert1}
	verifiedChain2 := []*x509.Certificate{cert2}
	trustedSignerCerts := []*x509.Certificate{trustedSignerCert}

	// Call the function with the sample input data
	chains := NewCertificateChains([][]*x509.Certificate{verifiedChain1, verifiedChain2}, trustedSignerCerts)

	// Check if the total number of chains is as expected
	expectedChainCount := len(verifiedChain1) + len(verifiedChain2) + len(trustedSignerCerts)
	if len(chains.CertificateChainList) != expectedChainCount {
		t.Errorf("Expected %d certificate chains, but got %d", expectedChainCount, len(chains.CertificateChainList))
	}

	// Check if each chain in the result contains at least one entry
	for _, chain := range chains.CertificateChainList {
		if len(chain.CertificateChainEntryList) == 0 {
			t.Errorf("Expected each certificate chain to contain at least one entry, but found an empty chain")
		}
	}

}

func generateSelfSignedCertificate(commonName string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}

func TestNewCertificateChainsFromEntry(t *testing.T) {
	// Create a sample CertificateChainEntry for testing
	chainEntry := &CertificateChainEntry{
		RawCertificate: []byte{0xff, 0xfe, 0x15, 0x13, 0x33},
	}

	// Call the function with the sample CertificateChainEntry
	chains := NewCertificateChainsFromEntry(chainEntry)

	// Check if the total number of chains is as expected (should be 1)
	if len(chains.CertificateChainList) != 1 {
		t.Errorf("Expected 1 certificate chain, but got %d", len(chains.CertificateChainList))
	}

	// Check if the total number of entries in the chain is as expected (should be 1)
	if len(chains.CertificateChainList[0].CertificateChainEntryList) != 1 {
		t.Errorf("Expected 1 certificate chain entry, but got %d", len(chains.CertificateChainList[0].CertificateChainEntryList))
	}

}
