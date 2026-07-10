package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

const userAgent = "scan7x/1.0 (bug-bounty recon)"

// maxRespBody caps how much we read from any single response.
const maxRespBody = 30 << 20 // 30 MiB

var (
	// dataClient talks to OSINT data-source APIs (follows redirects, generous timeout).
	dataClient *http.Client
	// longClient is for slow endpoints like the Wayback CDX API on large domains.
	longClient *http.Client
	// probeClient touches targets directly (short timeout, limited redirects).
	probeClient *http.Client
)

func initHTTP(perRequestTimeout time.Duration) {
	transport := func(timeout time.Duration) *http.Transport {
		return &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:          200,
			MaxIdleConnsPerHost:   20,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   timeout,
			ExpectContinueTimeout: 2 * time.Second,
		}
	}
	dataClient = &http.Client{
		Timeout:   45 * time.Second,
		Transport: transport(45 * time.Second),
	}
	longClient = &http.Client{
		Timeout:   100 * time.Second,
		Transport: transport(100 * time.Second),
	}
	probeClient = &http.Client{
		Timeout:   perRequestTimeout,
		Transport: transport(perRequestTimeout),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 8 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// httpGet performs a GET and returns the (capped) body and status code.
func httpGet(ctx context.Context, client *http.Client, rawURL string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if err != nil {
		return body, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// httpGetRetry retries on transport errors, 5xx and 429 with a small backoff.
func httpGetRetry(ctx context.Context, client *http.Client, rawURL string, attempts int) ([]byte, int, error) {
	var lastErr error
	var lastStatus int
	for i := 0; i < attempts; i++ {
		body, status, err := httpGet(ctx, client, rawURL, nil)
		if err == nil && status < 500 && status != 429 {
			return body, status, nil
		}
		lastStatus = status
		if err != nil {
			lastErr = err
		} else {
			lastErr = fmt.Errorf("http status %d", status)
		}
		select {
		case <-ctx.Done():
			return nil, lastStatus, ctx.Err()
		case <-time.After(time.Duration(i+1) * 800 * time.Millisecond):
		}
	}
	return nil, lastStatus, lastErr
}
