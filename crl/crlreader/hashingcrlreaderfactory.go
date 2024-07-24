package crlreader

import (
	"bufio"
	"encoding/base64"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/hashing"
	"github.com/gr33nbl00d/caddy-revocation-validator/core/pemreader"
	"os"
)

type HashingCRLReaderFactory struct {
}

func (H HashingCRLReaderFactory) newHashingCRLReader(crlFile *os.File) hashing.HashingReaderWrapper {
	var reader hashing.HashingReaderWrapper
	_, pemFile := pemreader.IsPemFile(crlFile)
	if pemFile {
		reader = H.newHashingPEMCRLReader(crlFile)
	} else {
		reader = H.newHashingDERCRLReader(crlFile)
	}
	return reader
}

func (H HashingCRLReaderFactory) newHashingDERCRLReader(crlReader *os.File) hashing.HashingReaderWrapper {
	var reader = hashing.HashingReaderWrapper{
		Reader: bufio.NewReader(crlReader),
	}
	return reader
}

func (H HashingCRLReaderFactory) newHashingPEMCRLReader(crlReader *os.File) hashing.HashingReaderWrapper {
	pemReader := pemreader.NewPemReader(bufio.NewReader(crlReader))
	decoder := base64.NewDecoder(base64.StdEncoding, &pemReader)

	var reader = hashing.HashingReaderWrapper{
		Reader: bufio.NewReader(decoder),
	}
	return reader

}
