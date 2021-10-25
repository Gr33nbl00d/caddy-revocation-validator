package hashing

import (
	"bufio"
	"crypto"
	"fmt"
	"hash"
	"os"
)

type HashingReaderWrapper struct {
	Reader             *bufio.Reader
	Signature          string
	CalculateSignature bool
	hash               hash.Hash
}

func (t HashingReaderWrapper) Read(bytes []byte) (int, error) {
	byteCount, err := t.Reader.Read(bytes)
	if t.CalculateSignature == true && err == nil {
		if byteCount == len(bytes) {
			t.hash.Write(bytes)
		} else {
			copiedBytes := make([]byte, byteCount)
			copiedByteCount := copy(copiedBytes[:], bytes[0:byteCount])
			if copiedByteCount != byteCount {
				return byteCount, fmt.Errorf("error while copy of signature bytes: %v", err)
			}
			t.hash.Write(copiedBytes)
		}
	}
	return byteCount, err
}

func (t HashingReaderWrapper) Peek(count int) ([]byte, error) {
	return t.Reader.Peek(count)
}

func (t *HashingReaderWrapper) StartHashCalculation(hash crypto.Hash) {
	t.CalculateSignature = true
	t.hash = hash.New()
}

func (t *HashingReaderWrapper) FinishHashCalculation() []byte {
	t.CalculateSignature = false
	return t.hash.Sum(nil)
}

func (t HashingReaderWrapper) Reset(file *os.File) {
	t.Reader.Reset(file)
}

func (t HashingReaderWrapper) Discard(offset int64) error {
	_, err := t.Reader.Discard(int(offset))
	if err != nil {
		return err
	}
	return nil
}
