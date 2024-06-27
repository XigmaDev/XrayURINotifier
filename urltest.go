package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/net/proxy"
)

func urlTestOverSocks(url string, proxyHost string, proxyPort int, timeout time.Duration) (int, int) {
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", proxyHost, proxyPort), nil, proxy.Direct)
	if err != nil {
		fmt.Printf("Failed to create SOCKS5 dialer: %v\n", err)
		return 0, 0
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	startTime := time.Now()
	response, err := client.Get(url)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return 0, 0
	}
	defer response.Body.Close()

	endTime := time.Now()
	latency := int(endTime.Sub(startTime).Milliseconds())

	_, err = io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Failed to read response body: %v\n", err)
		return 0, 0
	}

	return latency, response.StatusCode
}

func urlTest(log zerolog.Logger, proxyHost string, proxyPort int) int {
	url := "http://www.gstatic.com/generate_204"
	if proxyHost == "" {
		proxyHost = "localhost"
	}
	if proxyPort == 0 {
		proxyPort = 10808
	}

	timeout := 5 * time.Second

	latency, statusCode := urlTestOverSocks(url, proxyHost, proxyPort, timeout)
	if latency != 0 && statusCode != 0 {
		return latency
	} else {
		log.Error().Msg("Failed to retrieve latency and status code.")
		return 0
	}
}
