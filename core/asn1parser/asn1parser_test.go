package asn1parser

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"github.com/smallstep/assert"
	asn1crypto "golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
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
	time, err := ReadUtcTime(reader)
	assert.Nil(t, err)
	assert.True(t, expectedTime.Equal(*time))
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
	reader := bufio.NewReader(bytes.NewReader([]byte(byteData)))
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
