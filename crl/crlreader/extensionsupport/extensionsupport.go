package extensionsupport

import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/asn1parser"
	"math/big"
)

type AuthorityKeyIdentifier struct {
	Raw                       asn1.RawContent
	KeyIdentifier             []byte      `asn1:"tag:0,optional"`
	AuthorityCertIssuer       GeneralName `asn1:"tag:1,optional"`
	AuthorityCertSerialNumber *big.Int    `asn1:"tag:2,optional"`
}

type GeneralName struct {
	Raw                       asn1.RawContent
	OtherName                 asn1.RawValue `asn1:"tag:0,optional"`
	Rfc822Name                asn1.RawValue `asn1:"tag:1,ia5,optional"`
	DNSName                   asn1.RawValue `asn1:"tag:2,ia5,optional"`
	X400Address               asn1.RawValue `asn1:"tag:3,optional"`
	DirectoryName             asn1.RawValue `asn1:"tag:4,optional"`
	EdiPartyName              asn1.RawValue `asn1:"tag:5,optional"`
	UniformResourceIdentifier asn1.RawValue `asn1:"tag:6,ia5,optional"`
	IPAddress                 asn1.RawValue `asn1:"tag:7,optional"`
	RegisteredID              asn1.RawValue `asn1:"tag:8,optional"`
}

func (G GeneralName) GetGeneralNameType() (int, error) {
	reader := bufio.NewReader(bytes.NewReader(G.Raw))
	tagLength, err := asn1parser.PeekTagLength(reader, 0)
	if err != nil {
		return 0, err
	}
	if asn1parser.IsContextSpecificTag(tagLength) == false {
		return -1, errors.New("generalname content is invalid")
	}
	lastContextSpecificTag, err := findLastRecursiveContextSpecificTagInOrder(nil, reader, 0)
	if err != nil {
		return 0, err
	}
	return asn1parser.GetContextSpecificTagId(lastContextSpecificTag), nil
}

func findLastRecursiveContextSpecificTagInOrder(previous *asn1parser.TagLength, reader *bufio.Reader, offset int) (*asn1parser.TagLength, error) {
	//this coding is needed because asn1 parser of go has wrong handling of multiple nested optional fields.
	//in this case rawcontent is not the content of the struct but content from the last parent sequence
	tagLength, err := asn1parser.PeekTagLength(reader, offset)
	if err != nil {
		return nil, err
	}
	if asn1parser.IsContextSpecificTag(tagLength) {
		return findLastRecursiveContextSpecificTagInOrder(tagLength, reader, offset+int(tagLength.CalculateTLLength().Int64()))
	}
	return previous, nil
}

const OidCertExtSubjectKeyId = "2.5.29.14"
const OidCertExtAuthorityKeyId = "2.5.29.35"
const OidCrlExtCrlNumber = "2.5.29.20"

var handledCRLExtensions = map[string]bool{
	OidCertExtAuthorityKeyId: true,
	OidCrlExtCrlNumber:       true,
}

func FindExtension(oidString string, extensions *[]pkix.Extension) *pkix.Extension {
	for _, extension := range *extensions {
		if extension.Id.String() == oidString {
			return &extension
		}
	}
	return nil
}

func CheckForCriticalUnhandledCRLExtensions(extensions *[]pkix.Extension) error {
	//Unhandled CRL Extensions in general:
	//Delta CRL Indicator 2.5.29.27 - No delta list support (critical)
	//FreshestCRL 2.5.29.47 - No delta list support (non-critical)
	//Issuing Distribution Point 2.5.27.(Not needed as we get this information from cert to check) (non-critical)
	//Authority Information Access 1.3.6.1.5.5.7.1.1 - We expect the signing cert to be in the chain for now (non-critical)
	//Issuer Alternative Name 2.5.29.18 - Currently we only support normal issuer field as used in most cases (non-critical)
	for _, extension := range *extensions {
		if extension.Critical {
			extensionIdStr := extension.Id.String()
			if handledCRLExtensions[extensionIdStr] == false {
				return errors.New(fmt.Sprintf("unhandled critical crl extension %s", extensionIdStr))
			}
		}
	}
	return nil
}
