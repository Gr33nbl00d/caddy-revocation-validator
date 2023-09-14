package asn1parser

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	asn1crypto "golang.org/x/crypto/cryptobyte/asn1"
	"io"
	"math/big"
	"time"
)

type Asn1Reader interface {
	Read(p []byte) (int, error)
	Peek(n int) ([]byte, error)
}

type Length struct {
	Length     big.Int //number of bytes the value has
	LengthSize int     //number of bytes the length has
}

type TagLength struct {
	Tag    asn1crypto.Tag
	Length Length
}

// Complete length in byte of the tlv record
func (l TagLength) CalculateTLVLength() *big.Int {
	sum := big.NewInt(0)
	lengthSizeBigInt := big.NewInt(int64(l.Length.LengthSize))
	sum = sum.Add(sum, big.NewInt(1))
	sum = sum.Add(sum, lengthSizeBigInt)
	sum = sum.Add(sum, &l.Length.Length)
	return sum
}

// Complete length in byte of value
func (l TagLength) CalculateValueLength() *big.Int {
	sum := big.NewInt(0)
	sum = sum.Add(sum, &l.Length.Length)
	return sum
}

// Complete length in byte of length of the value
func (l TagLength) CalculateTLLength() *big.Int {
	sum := big.NewInt(0)
	lengthSizeBigInt := big.NewInt(int64(l.Length.LengthSize))
	sum = sum.Add(sum, lengthSizeBigInt)
	sum = sum.Add(sum, big.NewInt(1))
	return sum
}

type BitString struct {
	Bytes     []byte // bits packed into bytes.
	BitLength int    // length in bits.
}

func IsContextSpecificTagWithId(tagId int, tagLength *TagLength) bool {
	if IsContextSpecificTag(tagLength) {
		tag := GetContextSpecificTagId(tagLength)
		if tag == tagId {
			return true
		}
	}
	return false
}

func GetContextSpecificTagId(tagLength *TagLength) int {
	return (int)(tagLength.Tag & 0x0F)
}

func IsContextSpecificTag(tagLength *TagLength) bool {
	if (tagLength.Tag & 0xF0) == 0xa0 {
		return true
	}
	return false
}

func ReadUtcTime(reader Asn1Reader) (*time.Time, error) {
	lastUpdateUtcTag, err := ReadTagLength(reader)
	if err != nil {
		return nil, err
	}
	err = ExpectTag(lastUpdateUtcTag.Tag, asn1.TagUTCTime)
	if err != nil {
		return nil, err
	}
	lastUpdateUtcBytes, err := ReadExpectedBytes(reader, int(lastUpdateUtcTag.Length.Length.Int64()))
	if err != nil {
		return nil, err
	}
	utcTime, err := ParseUTCTime(lastUpdateUtcBytes)
	if err != nil {
		return nil, err
	}
	return utcTime, nil
}

func ParseBitString(reader Asn1Reader) (*BitString, error) {
	tagLength, err := ReadTagLength(reader)
	if err != nil {
		return nil, err
	}
	err = ExpectTag(asn1crypto.BIT_STRING, tagLength.Tag)
	if err != nil {
		return nil, err
	}
	readBytes, err := ReadExpectedBytes(reader, int(tagLength.Length.Length.Int64()))
	if err != nil {
		return nil, err
	}
	if len(readBytes) == 0 {
		return nil, errors.New("BitString is empty")
	}
	var ret BitString
	paddingBits := int(readBytes[0])
	if paddingBits > 7 ||
		len(readBytes) == 1 && paddingBits > 0 ||
		readBytes[len(readBytes)-1]&((1<<readBytes[0])-1) != 0 {
		return nil, errors.New("invalid padding bits in BIT STRING")
	}
	ret.BitLength = (len(readBytes)-1)*8 - paddingBits
	ret.Bytes = readBytes[1:]
	return &ret, nil
}

func ParseOctetString(reader Asn1Reader) (ret []byte, err error) {
	tagLength, err := ReadTagLength(reader)
	if err != nil {
		return nil, err
	}
	err = ExpectTag(asn1crypto.OCTET_STRING, tagLength.Tag)
	if err != nil {
		return nil, err
	}
	return ReadExpectedBytes(reader, int(tagLength.Length.Length.Int64()))
}

func ParseUTCTime(bytes []byte) (*time.Time, error) {
	const timeFormat = "060102150405Z0700"
	utcTimeString := string(bytes)
	utcTime, err := time.Parse(timeFormat, utcTimeString)
	if err != nil {
		utcTime, err = time.Parse(timeFormat, utcTimeString)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid time format detected %v", err)
	}

	if ser := utcTime.Format(timeFormat); ser != utcTimeString {
		return nil, errors.New("backward serialization of deserialized data did not result in the same data")
	}

	//utc does not support years later than 2050
	if utcTime.Year() >= 2050 {
		utcTime = utcTime.AddDate(-100, 0, 0)
	}
	return &utcTime, nil
}

func ReadStruct(reader Asn1Reader, value interface{}) error {
	tagLength, err := PeekTagLength(reader, 0)
	if err != nil {
		return err
	}
	err = ExpectTag(asn1crypto.SEQUENCE, tagLength.Tag)
	if err != nil {
		return err
	}
	tlvBytes, err := ReadTVLBytesWithLimit(reader, *tagLength, 81920)
	if err != nil {
		return err
	}
	rest, err := asn1.Unmarshal(tlvBytes, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return errors.New("trailing data after asn1 object")
	}
	return nil
}

func ReadTVLBytesWithLimit(reader Asn1Reader, tagLength TagLength, maxLength int64) ([]byte, error) {
	err := ExpectLengthNotGreater(big.NewInt(maxLength), &tagLength.Length.Length)
	if err != nil {
		return nil, err
	}
	size := CalculateWholeTLVLength(tagLength)
	return ReadExpectedBytes(reader, size)
}

func CalculateWholeTLVLength(tagLength TagLength) int {
	tlvHeaderLength := tagLength.Length.LengthSize + 1
	realLength := int(tagLength.Length.Length.Int64()) + tlvHeaderLength
	return realLength
}

func ExpectLengthNotGreater(expectedLength *big.Int, length *big.Int) error {
	if length.Cmp(expectedLength) == 1 {
		return fmt.Errorf("length of tag is greater than expected. Expected max length %s but length was %s", expectedLength, length)
	}
	return nil
}

func ReadTagLength(reader Asn1Reader) (*TagLength, error) {
	tag, err := ReadTag(reader)
	if err != nil {
		return nil, err
	}
	length, err := ReadLength(reader)
	if err != nil {
		return nil, err
	}
	return &TagLength{Tag: *tag, Length: *length}, nil
}

func PeekTagLength(reader Asn1Reader, offset int) (*TagLength, error) {
	tag, err := PeekTag(reader, offset)
	if err != nil {
		return nil, err
	}

	length, err := PeekLength(reader, offset+1)
	if err != nil {
		return nil, err
	}

	return &TagLength{Tag: *tag, Length: *length}, nil
}

func ExpectTag(expectedTag asn1crypto.Tag, tag asn1crypto.Tag) error {
	if expectedTag != tag {
		return fmt.Errorf("unexpected tag. Expected: %d but found %d", expectedTag, tag)
	}
	return nil
}

func ReadTag(reader Asn1Reader) (*asn1crypto.Tag, error) {
	readBytes, err := ReadExpectedBytes(reader, 1)
	if err != nil {
		return nil, err
	}
	tag := asn1crypto.Tag(readBytes[0])
	return &tag, err
}

func PeekTag(reader Asn1Reader, offset int) (*asn1crypto.Tag, error) {
	readBytes, err := PeekExpectedBytes(reader, 1, offset)
	if err != nil {
		return nil, err
	}
	tag := asn1crypto.Tag(readBytes[0])
	return &tag, nil
}

func ReadExpectedBytes(reader Asn1Reader, byteSize int) ([]byte, error) {
	readBytes := make([]byte, byteSize)
	err := ReadExpectedBytesRecursive(reader, byteSize, &readBytes, 0)
	if err != nil {
		return nil, err
	}
	return readBytes, nil
}

func ReadExpectedBytesRecursive(reader Asn1Reader, byteSize int, byteArray *[]byte, currentPosition int) error {
	bytesLeftToRead := byteSize - currentPosition
	readBytes := make([]byte, bytesLeftToRead)
	read, err := reader.Read(readBytes)
	if err != nil {
		if err == io.EOF {
			return fmt.Errorf("end of file reached while still expecting bytes %v", err)
		}
		return err
	}
	copyBytes(byteArray, readBytes, currentPosition, read)
	if read != bytesLeftToRead {
		err := ReadExpectedBytesRecursive(reader, byteSize, byteArray, currentPosition+read)
		if err != nil {
			return err
		}
	}
	return nil
}

func copyBytes(targetBytes *[]byte, bytesToAdd []byte, targetBytePosition int, countOfBytesToAdd int) {
	for i := targetBytePosition; i < targetBytePosition+countOfBytesToAdd; i++ {
		(*targetBytes)[i] = bytesToAdd[i-targetBytePosition]
	}
}

func PeekExpectedBytes(reader Asn1Reader, byteSize int, offset int) ([]byte, error) {
	read, err := reader.Peek(byteSize + offset)
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("end of file reached while still expecting bytes %v", err)
		} else {
			return nil, err
		}
	}
	readBytes := make([]byte, byteSize)
	copiedBytes := copy(readBytes[:], read[offset:(offset+byteSize)])
	if copiedBytes != byteSize {
		return nil, errors.New("error while copy of expected bytes")
	}

	return readBytes, nil
}

func ReadLength(reader Asn1Reader) (*Length, error) {
	sizeOfLength := 1
	length := new(big.Int)
	lengthOrSizeOfLength, err := ReadUint8(reader)
	if err != nil {
		return nil, err
	}
	if (lengthOrSizeOfLength & 0x80) == 0 {
		length.SetUint64(uint64(lengthOrSizeOfLength))
	} else {
		sizeOfLength = int(lengthOrSizeOfLength & 0x0F)
		length, err = ReadExpectedBigInt(reader, sizeOfLength)
		if err != nil {
			return nil, err
		}
		sizeOfLength = sizeOfLength + 1
	}
	return &Length{
		Length: *length, LengthSize: sizeOfLength,
	}, nil
}

func PeekLength(reader Asn1Reader, offset int) (*Length, error) {
	sizeOfLength := 1
	length := new(big.Int)
	lengthOrSizeOfLength, err := PeekUint8(reader, offset)
	if err != nil {
		return nil, err
	}
	if (lengthOrSizeOfLength & 0x80) == 0 {
		length.SetUint64(uint64(lengthOrSizeOfLength))
	} else {
		offset += 1
		sizeOfLength = int(lengthOrSizeOfLength & 0x0F)
		length, err = PeekExpectedBigInt(reader, sizeOfLength, offset)
		if err != nil {
			return nil, err
		}
		sizeOfLength = sizeOfLength + 1
	}
	return &Length{
		Length: *length, LengthSize: sizeOfLength,
	}, nil
}

func ReadExpectedBigInt(reader Asn1Reader, sizeOfLength int) (*big.Int, error) {
	length := new(big.Int)
	lengthBytes, err := ReadExpectedBytes(reader, sizeOfLength)
	if err != nil {
		return nil, err
	}

	length = length.SetBytes(lengthBytes)
	return length, nil
}

func ReadBigInt(reader Asn1Reader) (*big.Int, error) {
	length := new(big.Int)
	tagLength, err := ReadTagLength(reader)
	if err != nil {
		return nil, err
	}
	err = ExpectTag(asn1.TagInteger, tagLength.Tag)
	if err != nil {
		return nil, err
	}
	readBytes, err := ReadExpectedBytes(reader, int(tagLength.CalculateValueLength().Int64()))
	if err != nil {
		return nil, err
	}

	length = length.SetBytes(readBytes)
	return length, nil
}

func PeekExpectedBigInt(reader Asn1Reader, sizeOfLength int, offset int) (*big.Int, error) {
	length := new(big.Int)
	lengthBytes, err := PeekExpectedBytes(reader, sizeOfLength, offset)
	if err != nil {
		return nil, err
	}
	length = length.SetBytes(lengthBytes)
	return length, nil
}

func ReadUint8(reader Asn1Reader) (uint8, error) {
	readBytes, err := ReadExpectedBytes(reader, 1)
	if err != nil {
		return 0, err
	}

	return readBytes[0], nil
}

func PeekUint8(reader Asn1Reader, offset int) (uint8, error) {
	readBytes, err := PeekExpectedBytes(reader, 1, offset)
	if err != nil {
		return 0, err
	}
	return readBytes[0], nil
}

func ParseIssuerRDNSequence(cert *x509.Certificate) (*pkix.RDNSequence, error) {
	return ParseRDNSequence(cert.RawIssuer)
}

func ParseSubjectRDNSequence(cert *x509.Certificate) (*pkix.RDNSequence, error) {
	return ParseRDNSequence(cert.RawSubject)
}

func ParseRDNSequence(rdnData []byte) (*pkix.RDNSequence, error) {
	rdnObject := new(pkix.RDNSequence)
	reader := bufio.NewReader(bytes.NewReader(rdnData))
	err := ReadStruct(reader, rdnObject)
	if err != nil {
		return nil, fmt.Errorf("could not parse the RDNSequence: %v", err)
	}
	return rdnObject, nil
}
