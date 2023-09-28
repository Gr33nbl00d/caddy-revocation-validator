package crlstore

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"github.com/gr33nbl00d/caddy-revocation-validator/core"
	"github.com/gr33nbl00d/caddy-revocation-validator/crl/crlreader"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestASN1Serializer_SerializeMetaInfo(t *testing.T) {
	// Define the expected values
	expectedThisUpdate := time.Date(2022, time.December, 1, 0, 0, 0, 0, time.UTC)
	expectedNextUpdate := expectedThisUpdate.Add(time.Hour)

	issuer := pkix.Name{
		Country:      []string{"US"},
		Organization: []string{"Example Organization"},
		CommonName:   "Example Issuer",
	}
	// Create an example CRLMetaInfo with the expected values
	metaInfo := &crlreader.CRLMetaInfo{
		Issuer:     issuer.ToRDNSequence(),
		ThisUpdate: expectedThisUpdate,
		NextUpdate: expectedNextUpdate,
	}

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Serialize the example CRLMetaInfo
	serializedMetaInfoBytes, err := serializer.SerializeMetaInfo(metaInfo)
	assert.NoError(t, err)

	expectedHex := "30653045310b3009060355040613025553311d301b060355040a13144578616d706c65204f7267616e697a6174696f6e311730150603550403130e4578616d706c6520497373756572170d3232313230313030303030305a800d3232313230313031303030305a"

	resultHex := hex.EncodeToString(serializedMetaInfoBytes)

	assert.Equal(t, expectedHex, resultHex)
}

func TestASN1Serializer_DeserializeMetaInfo(t *testing.T) {
	exampleMetaInfoHex := "30653045310b3009060355040613025553311d301b060355040a13144578616d706c65204f7267616e697a6174696f6e311730150603550403130e4578616d706c6520497373756572170d3232313230313030303030305a800d3232313230313031303030305a"

	// Convert the hex-encoded string to bytes
	exampleMetaInfoBytes, err := hex.DecodeString(exampleMetaInfoHex)
	assert.NoError(t, err)

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Deserialize the hex-encoded example CRLMetaInfo into a CRLMetaInfo structure
	metaInfo, err := serializer.DeserializeMetaInfo(exampleMetaInfoBytes)
	assert.NoError(t, err)

	// Define the expected values
	expectedThisUpdate := time.Date(2022, time.December, 1, 0, 0, 0, 0, time.UTC)
	expectedNextUpdate := expectedThisUpdate.Add(time.Hour)

	// Compare the deserialized values to the expected values
	assert.Equal(t, expectedThisUpdate, metaInfo.ThisUpdate)
	assert.Equal(t, expectedNextUpdate, metaInfo.NextUpdate)
	assert.Equal(t, "CN=Example Issuer,O=Example Organization,C=US", metaInfo.Issuer.String())
}

func TestASN1Serializer_SerializeRevokedCert(t *testing.T) {
	// Create an example RevokedCertificate with a fixed date
	fixedTime := time.Date(2022, time.December, 1, 0, 0, 0, 0, time.UTC)
	exampleRevokedCert := &pkix.RevokedCertificate{
		SerialNumber:   big.NewInt(12345),
		RevocationTime: fixedTime,
	}

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Serialize the example RevokedCertificate
	serializedRevokedCertBytes, err := serializer.SerializeRevokedCert(exampleRevokedCert)
	assert.NoError(t, err)

	// Define the expected hex-encoded serialized string
	expectedHex := "301302023039170d3232313230313030303030305a"

	// Convert the serialized bytes to a hex-encoded string
	serializedHex := hex.EncodeToString(serializedRevokedCertBytes)

	// Compare the serialized hex string to the expected hex string
	assert.Equal(t, expectedHex, serializedHex)
}

func TestASN1Serializer_DeserializeRevokedCert(t *testing.T) {
	// Define the hex-encoded example RevokedCertificate data with a fixed date
	fixedTime := time.Date(2022, time.December, 1, 0, 0, 0, 0, time.UTC)
	exampleRevokedCertHex := "301302023039170d3232313230313030303030305a"
	exampleRevokedCertBytes, err := hex.DecodeString(exampleRevokedCertHex)
	assert.NoError(t, err)

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Deserialize the hex-encoded example RevokedCertificate into a RevokedCertificate structure
	revokedCert, err := serializer.DeserializeRevokedCert(exampleRevokedCertBytes)
	assert.NoError(t, err)

	expectedSerialNumber := big.NewInt(12345)
	expectedRevocationTime := fixedTime

	// Compare the deserialized values to the expected values
	assert.Equal(t, expectedSerialNumber, revokedCert.SerialNumber)
	assert.Equal(t, expectedRevocationTime.Unix(), revokedCert.RevocationTime.Unix())
}

func TestASN1Serializer_SerializeMetaInfoExt(t *testing.T) {
	// Create an example ExtendedCRLMetaInfo with fixed values
	exampleMetaInfoExt := &crlreader.ExtendedCRLMetaInfo{
		CRLNumber: big.NewInt(67890),
	}

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Serialize the example ExtendedCRLMetaInfo
	serializedMetaInfoExtBytes, err := serializer.SerializeMetaInfoExt(exampleMetaInfoExt)
	assert.NoError(t, err)

	expectedHex := "30058003010932"

	// Convert the serialized bytes to a hex-encoded string
	serializedHex := hex.EncodeToString(serializedMetaInfoExtBytes)

	// Compare the serialized hex string to the expected hex string
	assert.Equal(t, expectedHex, serializedHex)
}

func TestASN1Serializer_DeserializeMetaInfoExt(t *testing.T) {
	exampleMetaInfoExtHex := "30058003010932"
	exampleMetaInfoExtBytes, err := hex.DecodeString(exampleMetaInfoExtHex)
	assert.NoError(t, err)

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Deserialize the hex-encoded example ExtendedCRLMetaInfo into an ExtendedCRLMetaInfo structure
	metaInfoExt, err := serializer.DeserializeMetaInfoExt(exampleMetaInfoExtBytes)

	assert.NoError(t, err)

	expectedBaseCRLNumber := big.NewInt(67890)

	// Compare the deserialized values to the expected values
	assert.Equal(t, expectedBaseCRLNumber, metaInfoExt.CRLNumber)
}

func TestASN1Serializer_SerializeSignatureCert(t *testing.T) {
	examplePublicKey := &rsa.PublicKey{
		N: big.NewInt(12345),
		E: 65537, // Common RSA public exponent
	}
	exampleCert := &x509.Certificate{
		SerialNumber: big.NewInt(12345),
		Subject: pkix.Name{
			Organization:       []string{"Example Organization"},
			OrganizationalUnit: []string{"Example Organizational Unit"},
			CommonName:         "example.com",
		},
		Issuer: pkix.Name{
			Organization:       []string{"Example Organization"},
			OrganizationalUnit: []string{"Example Organizational Unit"},
			CommonName:         "example.com",
		},
		NotBefore:             time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		EmailAddresses:        []string{"test@example.com"},
		IPAddresses:           []net.IP{net.IPv4(192, 168, 1, 1), net.IPv6loopback},
		IsCA:                  false,
		BasicConstraintsValid: true,
		Signature:             []byte{0x30, 0x45, 0x02, 0x20, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		PublicKey:             *examplePublicKey,
	}

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Serialize the example x509.Certificate
	serializedCertBytes, err := serializer.SerializeSignatureCert(exampleCert)
	assert.NoError(t, err)

	expectedHex := "3082019a04000400040004000400043030450220123456789abcdef0112233445566778899aabbccddeeff0102030405060708090a0b0c0d0e0f10111213141502010402010030090202303902030100010201000202303930543000301613144578616d706c65204f7267616e697a6174696f6e301d131b4578616d706c65204f7267616e697a6174696f6e616c20556e697430003000300030001300130b6578616d706c652e636f6d3000300030543000301613144578616d706c65204f7267616e697a6174696f6e301d131b4578616d706c65204f7267616e697a6174696f6e616c20556e697430003000300030001300130b6578616d706c652e636f6d30003000170d3232303130313030303030305a170d3233303130313030303030305a020105300030003000300602010102010230000101ff0101000201000101000400040030003000300030120c1074657374406578616d706c652e636f6d3024041000000000000000000000ffffc0a8010104100000000000000000000000000000000130000101003000300030003000300030003000300030003000"

	// Convert the serialized bytes to a hex-encoded string
	serializedHex := hex.EncodeToString(serializedCertBytes)

	// Compare the serialized hex string to the expected hex string
	assert.Equal(t, expectedHex, serializedHex)
}

func TestASN1Serializer_DeserializeSignatureCert(t *testing.T) {
	crtFile, err := os.Open(testhelper.GetTestDataFilePath("testcert.der"))
	assert.NoError(t, err)
	defer crtFile.Close()
	if err != nil {
		t.Errorf("error occured %v", err)
	}
	crtBytes, err := os.ReadFile(crtFile.Name())
	assert.NoError(t, err)

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	cert, err := serializer.DeserializeSignatureCert(crtBytes)
	assert.NoError(t, err)

	expectedSerialNumber := big.NewInt(0)
	expectedSerialNumber.SetUint64(15994519719171511020)
	// Add other expected certificate fields here as needed

	// Compare the deserialized values to the expected values
	assert.Equal(t, expectedSerialNumber, cert.SerialNumber)
	// Add other comparisons for expected fields here as needed
}

func TestASN1Serializer_SerializeCRLLocations(t *testing.T) {
	// Create an example CRLLocations with fixed data
	exampleCRLLocations := &core.CRLLocations{
		CRLUrl:                "https://example.com/crl.crl",
		CRLFile:               "crl.crl",
		CRLDistributionPoints: []string{"http://crl1.example.com", "http://crl2.example.com"},
	}

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Serialize the example CRLLocations
	serializedCRLLocationsBytes, err := serializer.SerializeCRLLocations(exampleCRLLocations)
	assert.NoError(t, err)

	expectedHex := "305a30321317687474703a2f2f63726c312e6578616d706c652e636f6d1317687474703a2f2f63726c322e6578616d706c652e636f6d131b68747470733a2f2f6578616d706c652e636f6d2f63726c2e63726c130763726c2e63726c"

	// Convert the serialized bytes to a hex-encoded string
	serializedHex := hex.EncodeToString(serializedCRLLocationsBytes)

	// Compare the serialized hex string to the expected hex string
	assert.Equal(t, expectedHex, serializedHex)
}

func TestASN1Serializer_DeserializeCRLLocations(t *testing.T) {
	expectedHex := "305a30321317687474703a2f2f63726c312e6578616d706c652e636f6d1317687474703a2f2f63726c322e6578616d706c652e636f6d131b68747470733a2f2f6578616d706c652e636f6d2f63726c2e63726c130763726c2e63726c"

	// Convert the expected hex string to bytes
	expectedBytes, err := hex.DecodeString(expectedHex)
	assert.NoError(t, err)

	// Create an instance of ASN1Serializer
	serializer := ASN1Serializer{}

	// Deserialize the expected bytes into CRLLocations
	deserializedCRLLocations, err := serializer.DeserializeCRLLocations(expectedBytes)
	assert.NoError(t, err)

	// Create an example CRLLocations with fixed data to compare
	exampleCRLLocations := &core.CRLLocations{
		CRLUrl:                "https://example.com/crl.crl",
		CRLFile:               "crl.crl",
		CRLDistributionPoints: []string{"http://crl1.example.com", "http://crl2.example.com"},
	}

	// Compare the deserialized CRLLocations to the example
	assert.Equal(t, exampleCRLLocations, deserializedCRLLocations)
}
