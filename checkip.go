package main

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/rs/zerolog"
)

func CheckIp(log zerolog.Logger, xrayproxyURL string) ([]byte, time.Duration) {
	httpProxyURL, err := url.Parse(xrayproxyURL)
	if nil != err {
		log.Fatal().Err(err).Msg("failed to parse bot http proxy url")
	}
	httpClient := http.Client{
		Transport: &http.Transport{
			IdleConnTimeout:       10 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			Proxy:                 http.ProxyURL(httpProxyURL),
		},
		Timeout: time.Second * 10,
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		"https://myip.wtf/json",
		nil,
	)
	if nil != err {
		log.Fatal().Err(err).Msg("failed to initialize http request")
	}
	start := time.Now()
	res, err := httpClient.Do(req)
	if nil != err {
		log.Fatal().Err(err).Msg("failed to issue http request")
	}
	defer res.Body.Close()
	resBody, err := io.ReadAll(res.Body)
	if nil != err {
		log.Fatal().Err(err).Msg("failed to read response body")
	}
	log.Info().Msg(string(resBody))
	duration := time.Since(start)
	log.Info().Str("Delay:", string(duration))
	return resBody, duration
}
