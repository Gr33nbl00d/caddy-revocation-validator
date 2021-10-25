package ocsp

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/gr33nbl00d/caddy-tls-clr/config"
	"github.com/gr33nbl00d/caddy-tls-clr/core"
	"github.com/gr33nbl00d/caddy-tls-clr/core/asn1parser"
	"github.com/muesli/cache2go"
	"go.uber.org/zap"
	"golang.org/x/crypto/ocsp"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	maxClockSkew = 900 * time.Second
)

type OCSPRevocationChecker struct {
	ocspConfig *config.OCSPConfig
	logger     *zap.Logger
	cache      *cache2go.CacheTable
}

func (c *OCSPRevocationChecker) IsRevoked(clientCertificate *x509.Certificate, verifiedChains [][]*x509.Certificate) (*core.RevocationStatus, error) {
	subjectRDNSequence, err := asn1parser.ParseSubjectRDNSequence(clientCertificate)
	if err != nil {
		return nil, err
	}
	cacheKey := subjectRDNSequence.String() + "_" + clientCertificate.SerialNumber.String()
	cache, err := c.tryGetResponseFromCache(cacheKey)
	if err == nil {
		return cache, nil
	} else {
		c.logger.Debug("certificate not found in cache", zap.String("certificate", clientCertificate.Subject.String()), zap.Error(err))
	}

	chains := core.NewCertificateChains(verifiedChains, c.ocspConfig.TrustedResponderCerts)
	//TODO Support AIA via clientCertificate.IssuingCertificateURL
	issuer, err := asn1parser.ParseIssuerRDNSequence(clientCertificate)
	if err != nil {
		return nil, err
	}
	certCandidates, err := core.FindCertificateIssuerCandidates(issuer, &clientCertificate.Extensions, clientCertificate.PublicKeyAlgorithm, chains)
	ocspServerList := c.filterHTTPOCSPServers(clientCertificate.OCSPServer)
	var output []byte = nil
	for _, ocspServer := range ocspServerList {
		for _, certCandidate := range certCandidates {
			output, err = c.executeHttpRequest(ocspServer, clientCertificate, certCandidate.Certificate)
			if err != nil {
				c.logger.Debug("ocsp server revocation query failed", zap.String("ocsp_server", ocspServer), zap.Error(err))
				continue
			}

			if output == nil {
				continue
			}
			ocspResponse, err := c.parseOcspResponse(certCandidates, output, ocspServer)
			if err != nil {
				c.logger.Debug("failed to parse ocsp server response", zap.String("ocsp_server", ocspServer), zap.Error(err))
				continue
			}
			revocationStatus := core.RevocationStatus{
				Revoked:      false,
				OcspResponse: ocspResponse,
			}

			if ocspResponse.Status == ocsp.Revoked {
				revocationStatus = core.RevocationStatus{
					Revoked:      true,
					OcspResponse: ocspResponse,
				}
			}
			evictionTime := c.calculateEvictionTime(ocspResponse)
			if evictionTime > 0 {
				c.cache.Add(cacheKey, evictionTime, revocationStatus)
			}
			return &revocationStatus, nil
		}
	}
	if len(ocspServerList) > 0 && c.ocspConfig.OCSPAIAStrict {
		return nil, fmt.Errorf("failed to check revocation status on all ocsp servers: %v", ocspServerList)
	} else {
		c.logger.Warn("failed to check revocation status on all ocsp servers", zap.Strings("ocsp_servers", ocspServerList))
		return &core.RevocationStatus{
			Revoked: false,
		}, nil
	}

}

func (c *OCSPRevocationChecker) calculateEvictionTime(response *ocsp.Response) time.Duration {
	timeTillNextUpdate := response.NextUpdate.Sub(time.Now())
	if timeTillNextUpdate > 0 {
		return timeTillNextUpdate + maxClockSkew
	} else {
		return c.ocspConfig.DefaultCacheDurationParsed
	}
}

func (c *OCSPRevocationChecker) parseOcspResponse(certCandidates []*core.CertificateChainEntry, output []byte, ocspServer string) (*ocsp.Response, error) {
	ocspResponse, err := ocsp.ParseResponse(output, nil)
	if err == nil {
		return ocspResponse, nil
	}
	for _, certCandidate := range certCandidates {
		ocspResponse, err := ocsp.ParseResponse(output, certCandidate.Certificate)
		if err != nil {
			c.logger.Debug("failed to parse ocsp server response", zap.String("ocsp_server", ocspServer), zap.Error(err))
			continue
		}
		return ocspResponse, nil
	}
	return nil, errors.New("unable to parse ocsp response with any certificate available")
}

func (c *OCSPRevocationChecker) Provision(ocspConfig *config.OCSPConfig, logger *zap.Logger) error {
	c.ocspConfig = ocspConfig
	c.logger = logger
	return nil
}

func (c *OCSPRevocationChecker) Cleanup() error {
	if c.cache != nil {
		c.cache.Flush()
	}

	return nil
}

func (c *OCSPRevocationChecker) executeHttpRequest(ocspServer string, clientCert *x509.Certificate, issuerCert *x509.Certificate) ([]byte, error) {
	opts := &ocsp.RequestOptions{Hash: crypto.SHA1}
	buffer, err := ocsp.CreateRequest(clientCert, issuerCert, opts)
	if err != nil {
		return nil, err
	}
	httpRequest, err := c.prepareHttpRequest(ocspServer, buffer)
	if err != nil {
		return nil, err
	}
	httpClient := &http.Client{}
	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		return nil, err
	}
	defer httpResponse.Body.Close()
	output, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (c *OCSPRevocationChecker) prepareHttpRequest(ocspServer string, httpBody []byte) (*http.Request, error) {
	httpRequest, err := http.NewRequest(http.MethodPost, ocspServer, bytes.NewBuffer(httpBody))
	if err != nil {
		return nil, err
	}
	ocspUrl, err := url.Parse(ocspServer)
	if err != nil {
		return nil, err
	}
	httpRequest.Header.Add("Content-Type", "application/ocsp-request")
	httpRequest.Header.Add("Accept", "application/ocsp-response")
	httpRequest.Header.Add("host", ocspUrl.Host)
	return httpRequest, nil
}

func (c *OCSPRevocationChecker) filterHTTPOCSPServers(ocspServerList []string) []string {
	httpOcspUrls := make([]string, 0)
	for _, ocspServer := range ocspServerList {
		if strings.HasPrefix(strings.ToLower(ocspServer), "http") {
			httpOcspUrls = append(httpOcspUrls, ocspServer)
		}
	}
	return httpOcspUrls
}

func (c *OCSPRevocationChecker) tryGetResponseFromCache(cacheKey string) (*core.RevocationStatus, error) {
	c.cache = cache2go.Cache("ocsp_client")

	// Let's retrieve the item from the cache.
	res, err := c.cache.Value(cacheKey)
	if err == nil {
		response := res.Data().(core.RevocationStatus)
		return &response, nil
	} else {
		return nil, err
	}
}
