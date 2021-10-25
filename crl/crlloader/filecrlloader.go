package crlloader

import (
	"fmt"
	"github.com/gr33nbl00d/caddy-tls-clr/core/utils"
	"go.uber.org/zap"
	"io"
	"os"
)

type FileLoader struct {
	FileName string
	Logger   *zap.Logger
}

func (f FileLoader) LoadCRL(filePath string) error {
	err := utils.Retry(CRLLoaderRetryCount, CRLLoaderRetryDelay, f.Logger, func() error {
		return f.copyToTargetFile(filePath)
	})
	return err
}

func (f FileLoader) copyToTargetFile(filePath string) error {
	stat, err := os.Stat(f.FileName)
	if err != nil {
		return err
	}
	if stat.IsDir() {
		return fmt.Errorf("CRL File %s is a directory", f.FileName)
	}
	crlFile, err := os.OpenFile(filePath, os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer crlFile.Close()
	sourceFile, err := os.OpenFile(f.FileName, os.O_RDONLY|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	_, err = io.Copy(crlFile, sourceFile)
	if err != nil {
		return err
	}
	return nil
}

func (f FileLoader) GetCRLLocationIdentifier() (string, error) {
	return calculateHashHexString(f.FileName), nil
}

func (f FileLoader) GetDescription() string {
	return f.FileName
}
