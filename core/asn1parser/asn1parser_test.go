package asn1parser

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"github.com/gr33nbl00d/caddy-revocation-validator/testhelper"
	"github.com/smallstep/assert"
	asn1crypto "golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTagLength_CalculateTLVLength(t *testing.T) {
	// Create a test case with sample input values
	tag := asn1crypto.OCTET_STRING
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(5)
	length := Length{Length: *lengthBigInt, LengthSize: 2}
	tagLength := TagLength{Tag: tag, Length: length}

	// Call the function being tested
	result := tagLength.CalculateTLVLength()

	// Define the expected result based on your sample input
	expected := big.NewInt(8)

	// Compare the result with the expected value

	if result.Cmp(expected) != 0 {
		t.Errorf("Unexpected result. Got %v, want %v", result, expected)
	}
}

func TestTagLength_CalculateValueLength(t *testing.T) {
	// Create a test case with sample input values
	tag := asn1crypto.OCTET_STRING
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(5)
	length := Length{Length: *lengthBigInt, LengthSize: 2}
	tagLength := TagLength{Tag: tag, Length: length}

	// Call the function being tested
	result := tagLength.CalculateValueLength()

	// Define the expected result based on your sample input
	expected := big.NewInt(5)

	// Compare the result with the expected value

	if result.Cmp(expected) != 0 {
		t.Errorf("Unexpected result. Got %v, want %v", result, expected)
	}
}

func TestTagLength_CalculateTLLength(t *testing.T) {
	// Create a test case with sample input values
	tag := asn1crypto.OCTET_STRING
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(5)
	length := Length{Length: *lengthBigInt, LengthSize: 2}
	tagLength := TagLength{Tag: tag, Length: length}

	// Call the function being tested
	result := tagLength.CalculateTLLength()

	// Define the expected result based on your sample input
	expected := big.NewInt(3)

	// Compare the result with the expected value

	if result.Cmp(expected) != 0 {
		t.Errorf("Unexpected result. Got %v, want %v", result, expected)
	}
}

func TestIsContextSpecificTagWithId(t *testing.T) {
	tag := 0xa5
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(5)
	length := Length{Length: *lengthBigInt, LengthSize: 2}
	tagLength := TagLength{Tag: asn1crypto.Tag(tag), Length: length}

	result := IsContextSpecificTagWithId(5, &tagLength)
	assert.True(t, result)
}

func TestIsNoneContextSpecificTagWithId(t *testing.T) {
	tag := 0x5
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(5)
	length := Length{Length: *lengthBigInt, LengthSize: 2}
	tagLength := TagLength{Tag: asn1crypto.Tag(tag), Length: length}

	result := IsContextSpecificTagWithId(5, &tagLength)
	assert.False(t, result)
}
func TestReadUtcTime(t *testing.T) {

	expectedTime := time.Date(2015, time.April, 07, 22, 38, 55, 0, time.UTC)
	byteData, err := hex.DecodeString("170D3135303430373232333835355A")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	timeRead, err := ReadUtcTime(reader)
	assert.Nil(t, err)
	assert.True(t, expectedTime.Equal(*timeRead))
}

func TestReadUtcTimeWrongTag(t *testing.T) {

	byteData, err := hex.DecodeString("110D3135303430373232333835355A")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadUtcTime(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "unexpected tag. Expected: 17 but found 23", err.Error())
}

func TestReadUtcTimeCorruptTLV(t *testing.T) {

	byteData, err := hex.DecodeString("17")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadUtcTime(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestReadUtcTimeWithIncompleteData(t *testing.T) {

	byteData, err := hex.DecodeString("170D313530343037323233383535")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadUtcTime(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestReadUtcTimeWithInvalidTimeFormat(t *testing.T) {
	byteData, err := hex.DecodeString("170DF135303430373232333835355A")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadUtcTime(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "invalid time format detected parsing time \"\\xf150407223855Z\" as \"060102150405Z0700\": cannot parse \"\\xf150407223855Z\" as \"06\"", err.Error())
}

func TestReadUtcTimeWithYearAfter2050(t *testing.T) {
	expectedTime := time.Date(1955, time.April, 07, 22, 38, 55, 0, time.UTC)
	byteData, err := hex.DecodeString("170D3535303430373232333835355a")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result, err := ReadUtcTime(reader)
	assert.Nil(t, err)
	assert.True(t, expectedTime.Equal(*result))

}

func TestParseBitString(t *testing.T) {
	expectedBytes := []byte("ABCD")
	expectedBitString := BitString{Bytes: expectedBytes, BitLength: 32}
	byteData, err := hex.DecodeString("03050041424344")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result, err := ParseBitString(reader)
	assert.Nil(t, err)
	assert.Equals(t, expectedBitString.Bytes, result.Bytes)
	assert.Equals(t, expectedBitString.BitLength, result.BitLength)
}

func TestParseBitStringWithBitLengthNotAMultipleOf8(t *testing.T) {
	expectedBytes, err := hex.DecodeString("6E5DC0")
	assert.Nil(t, err)
	expectedBitString := BitString{Bytes: expectedBytes, BitLength: 18}
	byteData, err := hex.DecodeString("0304066e5dc0")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result, err := ParseBitString(reader)
	assert.Nil(t, err)
	assert.Equals(t, expectedBitString.Bytes, result.Bytes)
	assert.Equals(t, expectedBitString.BitLength, result.BitLength)
}

func TestParseBitStringWithIncorrectPadding1(t *testing.T) {
	byteData, err := hex.DecodeString("0304F66e5dc0")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseBitString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "invalid padding bits in BIT STRING", err.Error())
}

func TestParseBitStringWithPaddingButOnlySingleByte(t *testing.T) {
	byteData, err := hex.DecodeString("030106")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseBitString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "invalid padding bits in BIT STRING", err.Error())
}

func TestParseBitStringWithNoneZeroPaddingBits(t *testing.T) {
	byteData, err := hex.DecodeString("0304F66e5dcf")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseBitString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "invalid padding bits in BIT STRING", err.Error())
}

func TestParseEmptyBitString(t *testing.T) {
	byteData, err := hex.DecodeString("0300")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseBitString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "BitString is empty", err.Error())
}

func TestParseBitStringWithWrongTag(t *testing.T) {
	byteData, err := hex.DecodeString("05050041424344")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseBitString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "unexpected tag. Expected: 3 but found 5", err.Error())
}

func TestParseBitStringWithCorruptTLVData(t *testing.T) {
	byteData, err := hex.DecodeString("05")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseBitString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestParseBitStringWithIncompleteData(t *testing.T) {
	byteData, err := hex.DecodeString("030500414243")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseBitString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestParseOctetString(t *testing.T) {
	expectedBytes, err := hex.DecodeString("0123456789abcdef")
	assert.Nil(t, err)
	byteData, err := hex.DecodeString("04080123456789abcdef")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result, err := ParseOctetString(reader)
	assert.Nil(t, err)
	assert.Equals(t, expectedBytes, result)

}
func TestParseOctetStringFailingBecauseOfInvalidTLVLength(t *testing.T) {
	byteData, err := hex.DecodeString("04")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseOctetString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestParseOctetStringFailingBecauseOfInvalidTLVTag(t *testing.T) {
	byteData, err := hex.DecodeString("")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseOctetString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestParseOctetStringFailingBecauseOfNonOctetStringData(t *testing.T) {
	byteData, err := hex.DecodeString("050101")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ParseOctetString(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "unexpected tag. Expected: 4 but found 5", err.Error())
}

func TestCalculateWholeTLVLength(t *testing.T) {
	// Create a test case with sample input values
	tag := asn1crypto.OCTET_STRING
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(5)
	length := Length{Length: *lengthBigInt, LengthSize: 2}
	tagLength := TagLength{Tag: tag, Length: length}

	// Call the function being tested
	result := CalculateWholeTLVLength(tagLength)

	assert.Equals(t, 8, result)

}

func TestExpectLengthNotGreaterWithEqualValues(t *testing.T) {
	length1 := new(big.Int)
	length1.SetUint64(5)
	length2 := new(big.Int)
	length2.SetUint64(5)
	err := ExpectLengthNotGreater(length1, length2)
	assert.Nil(t, err)
}

func TestExpectLengthNotGreaterWithSmallerValue(t *testing.T) {
	length1 := new(big.Int)
	length1.SetUint64(6)
	length2 := new(big.Int)
	length2.SetUint64(5)
	err := ExpectLengthNotGreater(length1, length2)
	assert.Nil(t, err)
}

func TestExpectLengthNotGreaterWithGreaterValue(t *testing.T) {
	length1 := new(big.Int)
	length1.SetUint64(5)
	length2 := new(big.Int)
	length2.SetUint64(6)
	err := ExpectLengthNotGreater(length1, length2)
	assert.NotNil(t, err)
	assert.Equals(t, "length of tag is greater than expected. Expected max length 5 but length was 6", err.Error())
}

func TestReadStruct(t *testing.T) {
	expectedObjectIdentifier := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	expectedValue := new(pkix.AlgorithmIdentifier)
	expectedValue.Algorithm = expectedObjectIdentifier
	expectedRawByteData, err := hex.DecodeString("")
	assert.Nil(t, err)
	expectedRawFullByteData, err := hex.DecodeString("0500")
	assert.Nil(t, err)
	expectedValue.Parameters = asn1.RawValue{
		Class:      0,
		Tag:        5,
		IsCompound: false,
		Bytes:      expectedRawByteData,
		FullBytes:  expectedRawFullByteData,
	}
	byteData, err := hex.DecodeString("300D06092A864886F70D0101050500")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result := new(pkix.AlgorithmIdentifier)
	err = ReadStruct(reader, result)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equals(t, expectedObjectIdentifier, result.Algorithm)
	assert.Equals(t, expectedValue.Parameters, result.Parameters)
	assert.Equals(t, expectedValue, result)
}

func TestReadStructWrongTag(t *testing.T) {
	byteData, err := hex.DecodeString("040D06092A864886F70D0101050500")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result := new(pkix.AlgorithmIdentifier)
	err = ReadStruct(reader, result)
	assert.NotNil(t, err)
	assert.Equals(t, "unexpected tag. Expected: 48 but found 4", err.Error())
}

func TestReadStructInvalidTLVData(t *testing.T) {
	byteData, err := hex.DecodeString("30")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result := new(pkix.AlgorithmIdentifier)
	err = ReadStruct(reader, result)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestReadStructIncompleteData(t *testing.T) {
	byteData, err := hex.DecodeString("300D06092A864886F70D01010505")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result := new(pkix.AlgorithmIdentifier)
	err = ReadStruct(reader, result)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestReadStructInvalidDataContent(t *testing.T) {
	byteData, err := hex.DecodeString("300D30092A864886F70D0101050500")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result := new(pkix.AlgorithmIdentifier)
	err = ReadStruct(reader, result)
	assert.NotNil(t, err)
	assert.True(t, strings.HasPrefix(err.Error(), "asn1: structure error"))
}
func TestPeekTagLength(t *testing.T) {
	expectedTag := asn1crypto.OCTET_STRING
	expectedLengthBigInt := new(big.Int)
	expectedLengthBigInt.SetUint64(0x0d)
	expectedLength := Length{Length: *expectedLengthBigInt, LengthSize: 1}
	expectedTagLength := TagLength{Tag: expectedTag, Length: expectedLength}

	byteData, err := hex.DecodeString("040D")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result, err := PeekTagLength(reader, 0)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equals(t, expectedTagLength, *result)
	expectByteNotInfluencedByPeek, err := reader.ReadByte()
	assert.Nil(t, err)
	assert.NotNil(t, expectByteNotInfluencedByPeek)
	assert.True(t, expectByteNotInfluencedByPeek == 0x04)
}

func TestPeekTagLengthWithOffset(t *testing.T) {
	expectedTag := asn1crypto.OCTET_STRING
	expectedLengthBigInt := new(big.Int)
	expectedLengthBigInt.SetUint64(0x0d)
	expectedLength := Length{Length: *expectedLengthBigInt, LengthSize: 1}
	expectedTagLength := TagLength{Tag: expectedTag, Length: expectedLength}

	byteData, err := hex.DecodeString("FF040D")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result, err := PeekTagLength(reader, 1)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equals(t, expectedTagLength, *result)
	expectByteNotInfluencedByPeek, err := reader.ReadByte()
	assert.Nil(t, err)
	assert.NotNil(t, expectByteNotInfluencedByPeek)
	assert.True(t, expectByteNotInfluencedByPeek == 0xFF)
}

func TestPeekTagLengthWithInvalidTLVData(t *testing.T) {
	byteData, err := hex.DecodeString("")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = PeekTagLength(reader, 0)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestReadLengthOneByte(t *testing.T) {
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(0x0D)
	expectedLength := Length{Length: *lengthBigInt, LengthSize: 1}
	byteData, err := hex.DecodeString("0D")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	length, err := ReadLength(reader)
	assert.Nil(t, err)
	assert.NotNil(t, length)
	assert.Equals(t, expectedLength, *length)
}

func TestReadLengthTwoByte(t *testing.T) {
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(163)
	expectedLength := Length{Length: *lengthBigInt, LengthSize: 2}
	byteData, err := hex.DecodeString("81A3")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	length, err := ReadLength(reader)
	assert.Nil(t, err)
	assert.NotNil(t, length)
	assert.Equals(t, expectedLength, *length)
}

func TestReadLengthInvalidOneByteLength(t *testing.T) {
	byteData, err := hex.DecodeString("")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadLength(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())

}

func TestReadLengthInvalidTwoByteLength(t *testing.T) {
	byteData, err := hex.DecodeString("81")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadLength(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())

}

func TestPeekLengthOneByte(t *testing.T) {
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(0x0D)
	expectedLength := Length{Length: *lengthBigInt, LengthSize: 1}
	byteData, err := hex.DecodeString("0D")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	length, err := PeekLength(reader, 0)
	assert.Nil(t, err)
	assert.NotNil(t, length)
	assert.Equals(t, expectedLength, *length)
	expectByteNotInfluencedByPeek, err := reader.ReadByte()
	assert.Nil(t, err)
	assert.NotNil(t, expectByteNotInfluencedByPeek)
	assert.True(t, expectByteNotInfluencedByPeek == 0x0D)
}

func TestPeekLengthTwoByte(t *testing.T) {
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(163)
	expectedLength := Length{Length: *lengthBigInt, LengthSize: 2}
	byteData, err := hex.DecodeString("81A3")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	length, err := PeekLength(reader, 0)
	assert.Nil(t, err)
	assert.NotNil(t, length)
	assert.Equals(t, expectedLength, *length)
	expectByteNotInfluencedByPeek, err := reader.ReadByte()
	assert.Nil(t, err)
	assert.NotNil(t, expectByteNotInfluencedByPeek)
	assert.True(t, expectByteNotInfluencedByPeek == 0x81)
}

func TestPeekLengthWithOffset(t *testing.T) {
	lengthBigInt := new(big.Int)
	lengthBigInt.SetUint64(0x0D)
	expectedLength := Length{Length: *lengthBigInt, LengthSize: 1}
	byteData, err := hex.DecodeString("FF0D")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	length, err := PeekLength(reader, 1)
	assert.Nil(t, err)
	assert.NotNil(t, length)
	assert.Equals(t, expectedLength, *length)
	expectByteNotInfluencedByPeek, err := reader.ReadByte()
	assert.Nil(t, err)
	assert.NotNil(t, expectByteNotInfluencedByPeek)
	assert.True(t, expectByteNotInfluencedByPeek == 0xFF)
}

func TestPeekLengthInvalidOneByteLength(t *testing.T) {
	byteData, err := hex.DecodeString("")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = PeekLength(reader, 0)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())

}

func TestPeekLengthInvalidTwoByteLength(t *testing.T) {
	byteData, err := hex.DecodeString("81")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = PeekLength(reader, 0)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestReadBigInt(t *testing.T) {
	expectedBigInt := new(big.Int)
	expectedBigInt.SetUint64(4100)

	byteData, err := hex.DecodeString("02021004")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	result, err := ReadBigInt(reader)
	assert.Nil(t, err)
	assert.Equals(t, expectedBigInt, result)
}

func TestReadBigIntInvalidTag(t *testing.T) {
	byteData, err := hex.DecodeString("04021004")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadBigInt(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "unexpected tag. Expected: 2 but found 4", err.Error())
}

func TestReadBigIntInvalidTLV(t *testing.T) {
	byteData, err := hex.DecodeString("04")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadBigInt(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestReadBigIntIncompleteData(t *testing.T) {
	byteData, err := hex.DecodeString("020210")
	assert.Nil(t, err)
	reader := bufio.NewReader(bytes.NewReader(byteData))
	_, err = ReadBigInt(reader)
	assert.NotNil(t, err)
	assert.Equals(t, "end of file reached while still expecting bytes EOF", err.Error())
}

func TestParseRDNSequence(t *testing.T) {
	byteData, err := hex.DecodeString("308181310B3009060355040613025553310B3009060355040813024F523112301006035504071309426561766572746F6E310D300B060355040B1304534D4255310F300D060355040A13064D63416665653131302F060355040313284D634166656520534941205369676E696E6720436572746966696361746520417574686F72697479")
	assert.Nil(t, err)
	var (
		oidCountry            = []int{2, 5, 4, 6}
		oidOrganization       = []int{2, 5, 4, 10}
		oidOrganizationalUnit = []int{2, 5, 4, 11}
		oidCommonName         = []int{2, 5, 4, 3}
		localityName          = []int{2, 5, 4, 7}
		stateProvince         = []int{2, 5, 4, 8}
	)
	expectedResult := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidCountry, Value: "US"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: stateProvince, Value: "OR"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: localityName, Value: "Beaverton"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidOrganizationalUnit, Value: "SMBU"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidOrganization, Value: "McAfee"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidCommonName, Value: "McAfee SIA Signing Certificate Authority"},
		}}
	result, err := ParseRDNSequence(byteData)
	assert.Nil(t, err)
	assert.Equals(t, expectedResult.String(), result.String())
}

func TestParseRDNSequenceInvalidData(t *testing.T) {
	byteData, err := hex.DecodeString("048181310B3009060355040613025553310B3009060355040813024F523112301006035504071309426561766572746F6E310D300B060355040B1304534D4255310F300D060355040A13064D63416665653131302F060355040313284D634166656520534941205369676E696E6720436572746966696361746520417574686F72697479")
	assert.Nil(t, err)
	_, err = ParseRDNSequence(byteData)
	assert.NotNil(t, err)
	assert.Equals(t, "could not parse the RDNSequence: unexpected tag. Expected: 48 but found 4", err.Error())
}

func TestParseIssuerRDNSequence(t *testing.T) {
	var (
		oidCountry      = []int{2, 5, 4, 6}
		oidOrganization = []int{2, 5, 4, 10}
		oidCommonName   = []int{2, 5, 4, 3}
		stateProvince   = []int{2, 5, 4, 8}
	)
	expectedResult := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidCountry, Value: "UK"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: stateProvince, Value: "Test-State"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidOrganization, Value: "Golang Tests"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidCommonName, Value: "test-file"},
		}}

	crtFile, err := os.Open(testhelper.GetTestDataFilePath("testcert.der"))
	assert.Nil(t, err)
	defer utils.CloseWithErrorHandling(crtFile.Close)
	if err != nil {
		t.Errorf("error occured %v", err)
	}
	crtBytes, err := os.ReadFile(crtFile.Name())
	assert.Nil(t, err)
	cert, err := x509.ParseCertificate(crtBytes)
	assert.Nil(t, err)
	result, err := ParseIssuerRDNSequence(cert)
	assert.Nil(t, err)
	assert.Equals(t, expectedResult.String(), result.String())
}

func TestParseSubjectRDNSequence(t *testing.T) {
	var (
		oidCountry      = []int{2, 5, 4, 6}
		oidOrganization = []int{2, 5, 4, 10}
		oidCommonName   = []int{2, 5, 4, 3}
		stateProvince   = []int{2, 5, 4, 8}
	)
	expectedResult := pkix.RDNSequence{
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidCountry, Value: "UK"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: stateProvince, Value: "Test-State"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidOrganization, Value: "Golang Tests"},
		},
		pkix.RelativeDistinguishedNameSET{
			pkix.AttributeTypeAndValue{Type: oidCommonName, Value: "test-file"},
		}}

	crtFile, err := os.Open(testhelper.GetTestDataFilePath("testcert.der"))
	assert.Nil(t, err)
	defer utils.CloseWithErrorHandling(crtFile.Close)
	if err != nil {
		t.Errorf("error occured %v", err)
	}
	crtBytes, err := os.ReadFile(crtFile.Name())
	assert.Nil(t, err)
	cert, err := x509.ParseCertificate(crtBytes)
	assert.Nil(t, err)
	result, err := ParseSubjectRDNSequence(cert)
	assert.Nil(t, err)
	assert.Equals(t, expectedResult.String(), result.String())
}
