package extensionsupport

import (
	"crypto/x509/pkix"
	"github.com/stretchr/testify/suite"
	"testing"
)

type ExtensionsupportTestSuite struct {
	suite.Suite
}

// Helper function to create a pkix.Extension with the given OID and critical flag
func newExtension(oid []int, critical bool) pkix.Extension {
	return pkix.Extension{
		Id:       oid,
		Critical: critical,
	}
}

// Helper function to convert OID string into []int
func parseOID(oid string) []int {
	parts := make([]int, 0)
	for i := 0; i < len(oid); i++ {
		if oid[i] == '.' {
			continue
		}
		j := i
		for j < len(oid) && oid[j] != '.' {
			j++
		}
		val := 0
		for k := i; k < j; k++ {
			val = val*10 + int(oid[k]-'0')
		}
		parts = append(parts, val)
		i = j - 1
	}
	return parts
}

func (suite *ExtensionsupportTestSuite) TestCheckForCriticalUnhandledCRLExtensions_NoCriticalExtensions() {
	extensions := []pkix.Extension{
		newExtension(parseOID("1.2.3.4.5"), false),
		newExtension(parseOID("1.2.3.4.6"), false),
	}

	err := CheckForCriticalUnhandledCRLExtensions(&extensions)
	suite.Require().NoError(err)
}

func (suite *ExtensionsupportTestSuite) TestCheckForCriticalUnhandledCRLExtensions_KnownCriticalExtensions() {
	extensions := []pkix.Extension{
		newExtension(parseOID("2.5.29.35"), true),  // Authority Key Identifier
		newExtension(parseOID("2.5.29.20"), false), // CRL Number
	}

	err := CheckForCriticalUnhandledCRLExtensions(&extensions)
	suite.Require().NoError(err)
}

func (suite *ExtensionsupportTestSuite) TestCheckForCriticalUnhandledCRLExtensions_UnhandledCriticalExtensions() {
	extensions := []pkix.Extension{
		newExtension(parseOID("2.5.29.27"), true),          // Delta CRL Indicator
		newExtension(parseOID("1.3.6.1.5.5.7.1.1"), false), // Authority Information Access
	}

	err := CheckForCriticalUnhandledCRLExtensions(&extensions)
	suite.Require().Error(err)
	suite.Require().Equal("unhandled critical crl extension 2.5.29.27", err.Error())
}

// Test method for FindExtension
func (suite *ExtensionsupportTestSuite) TestFindExtension() {
	extensions := []pkix.Extension{
		newExtension(parseOID("2.5.29.35"), true),          // Authority Key Identifier
		newExtension(parseOID("2.5.29.20"), false),         // CRL Number
		newExtension(parseOID("1.3.6.1.5.5.7.1.1"), false), // Authority Information Access
	}

	// Test finding an existing extension
	oidToFind := "2.5.29.35"
	extension := FindExtension(oidToFind, &extensions)
	suite.Require().NotNil(extension)
	suite.Require().Equal(oidToFind, extension.Id.String())

	// Test finding a non-existent extension
	oidToFind = "1.2.3.4.5"
	extension = FindExtension(oidToFind, &extensions)
	suite.Require().Nil(extension)

	// Test with an empty list of extensions
	extensions = []pkix.Extension{}
	oidToFind = "2.5.29.35"
	extension = FindExtension(oidToFind, &extensions)
	suite.Require().Nil(extension)
}

func TestExtensionsupportTestSuite(t *testing.T) {
	suite.Run(t, new(ExtensionsupportTestSuite))
}
