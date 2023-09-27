package crlloader

import (
	"github.com/gr33nbl00d/caddy-revocation-validator/core/utils"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/url"
	"os"
)

type URLLoader struct {
	UrlString string
	Logger    *zap.Logger
}

func (L *URLLoader) LoadCRL(filePath string) error {
	normalizedUrl, err := L.normalizeUrl()
	if err != nil {
		return err
	}
	err = L.DownloadFromUrlWithRetries(filePath, normalizedUrl)
	if err != nil {
		return err
	}
	return nil
}

func (L *URLLoader) DownloadFromUrlWithRetries(filePath string, normalizedUrl string) error {
	err := utils.Retry(CRLLoaderRetryCount, CRLLoaderRetryDelay, L.Logger, func() error {
		return L.downloadCRL(normalizedUrl, filePath)
	})
	return err
}

func (L *URLLoader) GetCRLLocationIdentifier() (string, error) {
	normalizedUrl, err := L.normalizeUrl()
	if err != nil {
		return "", err
	}
	return calculateHashHexString(normalizedUrl), nil
}

func (L *URLLoader) GetDescription() string {
	return L.UrlString
}

func (L *URLLoader) downloadCRL(url string, filePath string) error {
	crlFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer crlFile.Close()
	httpRequest, err := http.Get(url)
	if err != nil {
		return err
	}
	defer httpRequest.Body.Close()
	_, err = io.Copy(crlFile, httpRequest.Body)
	if err != nil {
		return err
	}
	return nil
}

func (L *URLLoader) normalizeUrl() (string, error) {
	parse, err := url.Parse(L.UrlString)
	if err != nil {
		return "", err
	}

	normalizedUrl := parse.String()
	return normalizedUrl, nil
}
