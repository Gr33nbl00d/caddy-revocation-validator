package hashing

import (
	"bufio"
	"crypto"
	"encoding/hex"
	"github.com/smallstep/assert"
	"github.com/stretchr/testify/suite"
	"strings"
	"testing"
)

type HashingReaderWrapperTestSuite struct {
	suite.Suite
	sut    HashingReaderWrapper
	reader *bufio.Reader
}

// In order for 'go test' to run this suite, we need to create
// a normal test function and pass our suite to suite.Run
func TestHashingReaderWrapperTestSuite(t *testing.T) {
	suite.Run(t, new(HashingReaderWrapperTestSuite))
}

// Executed before each test
func (s *HashingReaderWrapperTestSuite) SetupTest() {
	s.sut = HashingReaderWrapper{
		Reader: bufio.NewReader(strings.NewReader("somebytestoread")),
	}
}

func (s *HashingReaderWrapperTestSuite) TestStartFinishCalculation() {
	assert.False(s.T(), s.sut.CalculateSignature)
	assert.Nil(s.T(), s.sut.hash)

	s.sut.StartHashCalculation(crypto.SHA512)

	assert.NotNil(s.T(), s.sut.hash)
	assert.True(s.T(), s.sut.CalculateSignature)

	result := s.sut.FinishHashCalculation()
	assert.False(s.T(), s.sut.CalculateSignature)
	assert.NotNil(s.T(), result)
}

func (s *HashingReaderWrapperTestSuite) TestHashOf5Bytes() {

	var buffer = make([]byte, 5)

	assert.False(s.T(), s.sut.CalculateSignature)
	assert.Nil(s.T(), s.sut.hash)

	s.sut.StartHashCalculation(crypto.SHA512)

	assert.NotNil(s.T(), s.sut.hash)
	assert.True(s.T(), s.sut.CalculateSignature)

	read, err := s.sut.Read(buffer)
	assert.Equals(s.T(), 5, read)
	assert.Nil(s.T(), err)

	resultHash := s.sut.FinishHashCalculation()
	assert.False(s.T(), s.sut.CalculateSignature)

	resultHashHex := hex.EncodeToString(resultHash)
	assert.Equals(s.T(), "75c33fcac3113bf8aeeede1d4243ba4cab52fb249e98b5692ee03463fc418ce421bfdf8f1d9b74cbf22143f32716cac2bbc5077d98c6c7941af26faf734c5b44", resultHashHex)
}

func (s *HashingReaderWrapperTestSuite) TestHashOf5BytesAfter2ByteRead() {
	s.sut = HashingReaderWrapper{
		Reader: bufio.NewReader(strings.NewReader("  somebytestoread")),
	}

	var buffer = make([]byte, 5)

	assert.False(s.T(), s.sut.CalculateSignature)
	assert.Nil(s.T(), s.sut.hash)

	//read 2 empty bytes before starting signature calculation
	var smallbuffer = make([]byte, 2)
	read, err := s.sut.Read(smallbuffer)
	assert.Equals(s.T(), 2, read)
	assert.Nil(s.T(), err)

	s.sut.StartHashCalculation(crypto.SHA512)

	assert.NotNil(s.T(), s.sut.hash)
	assert.True(s.T(), s.sut.CalculateSignature)

	read, err = s.sut.Read(buffer)
	assert.Equals(s.T(), 5, read)
	assert.Nil(s.T(), err)

	resultHash := s.sut.FinishHashCalculation()
	assert.False(s.T(), s.sut.CalculateSignature)

	resultHashHex := hex.EncodeToString(resultHash)
	assert.Equals(s.T(), "75c33fcac3113bf8aeeede1d4243ba4cab52fb249e98b5692ee03463fc418ce421bfdf8f1d9b74cbf22143f32716cac2bbc5077d98c6c7941af26faf734c5b44", resultHashHex)
}
func (s *HashingReaderWrapperTestSuite) TestHashOf5BytesAWithPeek() {

	var buffer = make([]byte, 5)

	assert.False(s.T(), s.sut.CalculateSignature)
	assert.Nil(s.T(), s.sut.hash)

	s.sut.StartHashCalculation(crypto.SHA512)

	assert.NotNil(s.T(), s.sut.hash)
	assert.True(s.T(), s.sut.CalculateSignature)

	read, err := s.sut.Read(buffer)
	assert.Equals(s.T(), 5, read)
	assert.Nil(s.T(), err)

	peek, err := s.sut.Peek(2)
	assert.Nil(s.T(), err)
	assert.Equals(s.T(), []byte("yt"), peek)

	resultHash := s.sut.FinishHashCalculation()
	assert.False(s.T(), s.sut.CalculateSignature)

	resultHashHex := hex.EncodeToString(resultHash)
	assert.Equals(s.T(), "75c33fcac3113bf8aeeede1d4243ba4cab52fb249e98b5692ee03463fc418ce421bfdf8f1d9b74cbf22143f32716cac2bbc5077d98c6c7941af26faf734c5b44", resultHashHex)
}
