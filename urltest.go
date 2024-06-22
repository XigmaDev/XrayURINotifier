package main

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"golang.org/x/net/proxy"
)

func urlTestOverSocks(url string, proxyHost string, proxyPort int, timeout time.Duration) (int, int) {
	// Dialer for SOCKS5 proxy
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("%s:%d", proxyHost, proxyPort), nil, proxy.Direct)
	if err != nil {
		fmt.Printf("Failed to create SOCKS5 dialer: %v\n", err)
		return 0, 0
	}

	// Transport that uses the SOCKS5 dialer
	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	// HTTP client with the transport
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	// Measure request time
	startTime := time.Now()
	response, err := client.Get(url)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return 0, 0
	}
	defer response.Body.Close()

	endTime := time.Now()
	latency := int(endTime.Sub(startTime).Milliseconds())

	// Read response body to ensure the request is fully completed
	_, err = io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Failed to read response body: %v\n", err)
		return 0, 0
	}

	return latency, response.StatusCode
}

func urlTest() int {
	url := "http://www.gstatic.com/generate_204"
	proxyHost := "localhost"
	proxyPort := 10808
	timeout := 5 * time.Second

	latency, statusCode := urlTestOverSocks(url, proxyHost, proxyPort, timeout)
	if latency != 0 && statusCode != 0 {
		return latency
	} else {
		fmt.Println("Failed to retrieve latency and status code.")
		return 0
	}
}
