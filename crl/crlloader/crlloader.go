package crlloader

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

type CRLLoader interface {
	LoadCRL(filePath string) error
	GetCRLLocationIdentifier() (string, error)
	GetDescription() string
}

const CRLLoaderRetryCount = 5
const CRLLoaderRetryDelay = 500 * time.Millisecond

func calculateHashHexString(normalizedUrl string) string {
	hash := sha256.New()
	hash.Write([]byte(normalizedUrl))
	sum := hash.Sum(nil)
	return hex.EncodeToString(sum)
}
